rule TTP_XOR_WriteProcessMemory_cc22 {
  strings:
    $key_cc22 = { 9b 50 [2] a9 72 [2] af 47 [2] 81 47 [2] be 5b }

  condition:
    any of them
}