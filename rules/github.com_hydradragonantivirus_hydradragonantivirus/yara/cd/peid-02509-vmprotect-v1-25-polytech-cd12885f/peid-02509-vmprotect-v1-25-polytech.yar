rule PEiD_02509_VMProtect_v1_25_____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 --> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F B7 06 }

  condition:
    $a
}