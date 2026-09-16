rule PEiD_00441_Crypto_Lock_v2_02__Eng_____Ryan_Thian_ {
  meta:
    description = "[Crypto-Lock v2.02 (Eng) -> Ryan Thian]"
    ep_only     = "true"

  strings:
    $a = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }

  condition:
    $a
}