rule PEiD_00018_624__Six_to_Four__v1_0_ {
  meta:
    description = "[624 (Six to Four) v1.0]"
    ep_only     = "true"

  strings:
    $a = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED }

  condition:
    $a
}