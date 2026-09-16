rule PEiD_03456_Windows_Type_1_font_metric_file_ {
  meta:
    description = "[Windows Type 1 font metric file]"
    ep_only     = "false"

  strings:
    $a = { 00 01 ?? ?? 00 00 43 6F 70 79 72 69 67 68 74 20 }

  condition:
    $a
}