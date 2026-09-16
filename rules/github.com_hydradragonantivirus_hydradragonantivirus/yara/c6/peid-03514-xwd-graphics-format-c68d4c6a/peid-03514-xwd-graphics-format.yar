rule PEiD_03514_XWD_graphics_format_ {
  meta:
    description = "[XWD graphics format]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 71 00 00 00 07 00 00 00 02 00 00 00 }

  condition:
    $a
}