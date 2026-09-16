rule PEiD_02067_shoooo_s_Pack____shoooo_ {
  meta:
    description = "[shoooo's Pack -> shoooo]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }

  condition:
    $a
}