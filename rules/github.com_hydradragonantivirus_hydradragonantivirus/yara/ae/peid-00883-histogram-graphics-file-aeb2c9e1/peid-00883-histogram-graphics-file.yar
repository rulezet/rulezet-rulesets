rule PEiD_00883_Histogram_graphics_file_ {
  meta:
    description = "[Histogram graphics file]"
    ep_only     = "false"

  strings:
    $a = { 6D 68 77 61 6E 68 00 04 01 02 01 02 }

  condition:
    $a
}