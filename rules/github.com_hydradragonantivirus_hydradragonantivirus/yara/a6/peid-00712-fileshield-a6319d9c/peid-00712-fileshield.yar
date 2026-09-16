rule PEiD_00712_FileShield_ {
  meta:
    description = "[FileShield]"
    ep_only     = "true"

  strings:
    $a = { 50 1E EB ?? 90 00 00 8B D8 }

  condition:
    $a
}