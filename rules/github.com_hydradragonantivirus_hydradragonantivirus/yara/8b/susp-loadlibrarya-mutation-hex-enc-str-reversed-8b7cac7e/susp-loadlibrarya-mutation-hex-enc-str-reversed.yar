rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_hex_enc_str_reversed = "14972716272696c44616f6c4" nocase ascii wide

  condition:
    all of them
}