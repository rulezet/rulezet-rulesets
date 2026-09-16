rule TTP_XOR_WriteProcessMemory_cca6 {
  strings:
    $key_cca6 = { 9b d4 [2] a9 f6 [2] af c3 [2] 81 c3 [2] be df }

  condition:
    any of them
}