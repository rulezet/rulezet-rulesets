rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_hex_enc_str_b64_enc_str = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" nocase ascii wide

  condition:
    all of them
}