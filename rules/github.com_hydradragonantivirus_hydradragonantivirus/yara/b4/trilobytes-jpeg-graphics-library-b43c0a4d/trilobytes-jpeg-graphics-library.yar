import "pe"
rule _Trilobytes_JPEG_graphics_Library_ {
  meta:
    description = "Trilobyte's JPEG graphics Library"

  strings:
    $0 = { 84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00 }

  condition:
    $0 at pe.entry_point
}