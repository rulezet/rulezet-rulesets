rule PEiD_02031_SCAN__AV_ {
  meta:
    description = "[SCAN /AV]"
    ep_only     = "true"

  strings:
    $a = { 1E 0E 1F B8 ?? ?? 8E C0 26 8A 1E ?? ?? 80 ?? ?? 72 }

  condition:
    $a
}