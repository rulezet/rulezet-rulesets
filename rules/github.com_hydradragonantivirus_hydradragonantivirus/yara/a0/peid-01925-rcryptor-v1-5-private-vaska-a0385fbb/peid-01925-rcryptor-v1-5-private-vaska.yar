rule PEiD_01925_RCryptor_v1_5__Private_____Vaska_ {
  meta:
    description = "[RCryptor v1.5 (Private) -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

  condition:
    $a
}