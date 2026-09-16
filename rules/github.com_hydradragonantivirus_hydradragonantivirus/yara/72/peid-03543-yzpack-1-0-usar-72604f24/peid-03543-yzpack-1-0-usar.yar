rule PEiD_03543_yzPack_1_0____UsAr_ {
  meta:
    description = "[yzPack 1.0 -> UsAr]"
    ep_only     = "true"

  strings:
    $a = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C }

  condition:
    $a
}