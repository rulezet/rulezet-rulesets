rule PEiD_02218_The_aPE_Inline_Patch_Basic__Advanced__Stealth__ {
  meta:
    description = "[The aPE Inline Patch Basic, Advanced, Stealth)]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? ?? 00 E8 ?? ?? 00 00 89 01 68 }

  condition:
    $a
}