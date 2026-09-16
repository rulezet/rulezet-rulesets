rule TTP_XOR_WriteProcessMemory_cca1 {
  strings:
    $key_cca1 = { 9b d3 [2] a9 f1 [2] af c4 [2] 81 c4 [2] be d8 }

  condition:
    any of them
}