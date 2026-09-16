rule TTP_XOR_WriteProcessMemory_ccf0 {
  strings:
    $key_ccf0 = { 9b 82 [2] a9 a0 [2] af 95 [2] 81 95 [2] be 89 }

  condition:
    any of them
}