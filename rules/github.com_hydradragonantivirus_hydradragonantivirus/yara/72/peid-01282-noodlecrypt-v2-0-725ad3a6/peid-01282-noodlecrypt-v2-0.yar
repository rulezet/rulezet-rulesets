rule PEiD_01282_NoodleCrypt_v2_0_ {
  meta:
    description = "[NoodleCrypt v2.0]"
    ep_only     = "true"

  strings:
    $a = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }

  condition:
    $a
}