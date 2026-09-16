rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas_xor {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_hex_enc_str_commas_xor = "4c,6f,61,64,4c,69,62,72,61,72,79,41" xor(0x01-0xff) ascii wide

  condition:
    all of them
}