rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_hex_enc_str_b64_enc_str = "NmI2NTcyNmU2NTZjMzMzMg==" nocase ascii wide

  condition:
    all of them
}