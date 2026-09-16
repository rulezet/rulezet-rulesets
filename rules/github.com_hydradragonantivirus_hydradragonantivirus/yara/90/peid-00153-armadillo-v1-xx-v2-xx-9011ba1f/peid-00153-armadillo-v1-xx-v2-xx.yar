rule PEiD_00153_Armadillo_v1_xx___v2_xx_ {
  meta:
    description = "[Armadillo v1.xx - v2.xx]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }

  condition:
    $a
}