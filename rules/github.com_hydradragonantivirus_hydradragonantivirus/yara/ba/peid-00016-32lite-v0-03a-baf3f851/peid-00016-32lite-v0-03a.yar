rule PEiD_00016_32Lite_v0_03a_ {
  meta:
    description = "[32Lite v0.03a]"
    ep_only     = "true"

  strings:
    $a = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }

  condition:
    $a
}