rule PEiD_00965_Krypton_v0_5_ {
  meta:
    description = "[Krypton v0.5]"
    ep_only     = "true"

  strings:
    $a = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }

  condition:
    $a
}