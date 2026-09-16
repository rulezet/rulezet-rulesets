rule PEiD_00884_Hitachi_Raster_Format_graphics_format_ {
  meta:
    description = "[Hitachi Raster Format graphics format]"
    ep_only     = "false"

  strings:
    $a = "CADC/KR RST"

  condition:
    $a
}