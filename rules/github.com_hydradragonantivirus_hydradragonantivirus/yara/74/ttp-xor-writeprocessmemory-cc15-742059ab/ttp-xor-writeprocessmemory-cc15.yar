rule TTP_XOR_WriteProcessMemory_cc15 {
  strings:
    $key_cc15 = { 9b 67 [2] a9 45 [2] af 70 [2] 81 70 [2] be 6c }

  condition:
    any of them
}