rule PEiD_00005__EPack_1_4_lite__final____by_6aHguT_ {
  meta:
    description = "[!EPack 1.4 lite (final) - by 6aHguT]"
    ep_only     = "true"

  strings:
    $a = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

  condition:
    $a
}