rule TTP_XOR_WriteProcessMemory_ccf6 {
  strings:
    $key_ccf6 = { 9b 84 [2] a9 a6 [2] af 93 [2] 81 93 [2] be 8f }

  condition:
    any of them
}