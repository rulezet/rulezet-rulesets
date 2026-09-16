rule TTP_XOR_WriteProcessMemory_ccf5 {
  strings:
    $key_ccf5 = { 9b 87 [2] a9 a5 [2] af 90 [2] 81 90 [2] be 8c }

  condition:
    any of them
}