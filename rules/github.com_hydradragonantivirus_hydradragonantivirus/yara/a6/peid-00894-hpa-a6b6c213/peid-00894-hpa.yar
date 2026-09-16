rule PEiD_00894_HPA_ {
  meta:
    description = "[HPA]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3 }

  condition:
    $a
}