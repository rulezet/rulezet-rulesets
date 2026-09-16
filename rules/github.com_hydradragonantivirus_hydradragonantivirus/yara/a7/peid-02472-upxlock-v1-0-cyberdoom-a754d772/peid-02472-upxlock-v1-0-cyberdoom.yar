rule PEiD_02472_UPXLock_v1_0____CyberDoom_ {
  meta:
    description = "[UPXLock v1.0 -> CyberDoom]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }

  condition:
    $a
}