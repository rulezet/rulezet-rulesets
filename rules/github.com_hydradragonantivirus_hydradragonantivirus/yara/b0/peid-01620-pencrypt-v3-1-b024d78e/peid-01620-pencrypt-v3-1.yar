rule PEiD_01620_PEncrypt_v3_1_ {
  meta:
    description = "[PEncrypt v3.1]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? ?? 00 F0 0F C6 }

  condition:
    $a
}