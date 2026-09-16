rule PEiD_00411_Creative_Audio_file_ {
  meta:
    description = "[Creative Audio file]"
    ep_only     = "false"

  strings:
    $a = "Creative Voice File"

  condition:
    $a
}