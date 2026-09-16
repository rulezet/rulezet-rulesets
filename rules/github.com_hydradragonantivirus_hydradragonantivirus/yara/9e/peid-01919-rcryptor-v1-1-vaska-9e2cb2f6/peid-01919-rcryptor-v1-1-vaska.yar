rule PEiD_01919_RCryptor_v1_1_____Vaska_ {
  meta:
    description = "[RCryptor v1.1 --> Vaska]"
    ep_only     = "false"

  strings:
    $a = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }

  condition:
    $a
}