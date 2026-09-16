rule PEiD_01933_RCryptor_v1_6d_____Vaska_ {
  meta:
    description = "[RCryptor v1.6d --> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }

  condition:
    $a
}