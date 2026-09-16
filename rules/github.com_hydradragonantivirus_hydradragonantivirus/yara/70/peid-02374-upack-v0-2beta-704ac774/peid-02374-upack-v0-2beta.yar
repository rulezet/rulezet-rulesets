rule PEiD_02374_Upack_v0_2Beta_ {
  meta:
    description = "[Upack v0.2Beta]"
    ep_only     = "true"

  strings:
    $a = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }

  condition:
    $a
}