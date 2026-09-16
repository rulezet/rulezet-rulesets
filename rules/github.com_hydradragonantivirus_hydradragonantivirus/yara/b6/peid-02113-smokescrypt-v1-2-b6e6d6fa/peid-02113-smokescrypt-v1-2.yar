rule PEiD_02113_SmokesCrypt_v1_2_ {
  meta:
    description = "[SmokesCrypt v1.2]"
    ep_only     = "true"

  strings:
    $a = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

  condition:
    $a
}