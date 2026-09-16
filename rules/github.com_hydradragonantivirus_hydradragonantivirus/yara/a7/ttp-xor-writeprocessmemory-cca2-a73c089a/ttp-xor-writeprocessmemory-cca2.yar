rule TTP_XOR_WriteProcessMemory_cca2 {
  strings:
    $key_cca2 = { 9b d0 [2] a9 f2 [2] af c7 [2] 81 c7 [2] be db }

  condition:
    any of them
}