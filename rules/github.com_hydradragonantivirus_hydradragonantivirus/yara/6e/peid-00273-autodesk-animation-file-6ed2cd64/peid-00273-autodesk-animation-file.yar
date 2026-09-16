rule PEiD_00273_AutoDesk_Animation_file_ {
  meta:
    description = "[AutoDesk Animation file]"
    ep_only     = "false"

  strings:
    $a = { ?? ?? ?? 00 12 AF ?? ?? 40 01 C8 }

  condition:
    $a
}