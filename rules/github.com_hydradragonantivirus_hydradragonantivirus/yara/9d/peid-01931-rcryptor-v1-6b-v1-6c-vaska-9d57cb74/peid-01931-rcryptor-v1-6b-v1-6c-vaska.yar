rule PEiD_01931_RCryptor_v1_6b___v1_6c____Vaska_ {
  meta:
    description = "[RCryptor v1.6b / v1.6c -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

  condition:
    $a
}