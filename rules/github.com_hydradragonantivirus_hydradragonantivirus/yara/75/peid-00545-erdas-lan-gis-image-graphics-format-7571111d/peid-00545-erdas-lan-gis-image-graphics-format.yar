rule PEiD_00545_Erdas_LAN_GIS_Image_graphics_format_ {
  meta:
    description = "[Erdas LAN/GIS Image graphics format]"
    ep_only     = "false"

  strings:
    $a = { 48 45 41 44 37 34 00 00 03 00 }

  condition:
    $a
}