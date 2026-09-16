rule PEiD_01439_Packanoid_v1____Arkanoid_ {
  meta:
    description = "[Packanoid v1 -> Arkanoid]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }

  condition:
    $a
}