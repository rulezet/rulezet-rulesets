rule PEiD_02172_SVK_Protector_v1_11_ {
  meta:
    description = "[SVK-Protector v1.11]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }

  condition:
    $a
}