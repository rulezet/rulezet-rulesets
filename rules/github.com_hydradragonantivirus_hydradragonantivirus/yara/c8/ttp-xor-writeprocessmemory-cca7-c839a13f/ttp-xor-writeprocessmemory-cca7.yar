rule TTP_XOR_WriteProcessMemory_cca7 {
  strings:
    $key_cca7 = { 9b d5 [2] a9 f7 [2] af c2 [2] 81 c2 [2] be de }

  condition:
    any of them
}