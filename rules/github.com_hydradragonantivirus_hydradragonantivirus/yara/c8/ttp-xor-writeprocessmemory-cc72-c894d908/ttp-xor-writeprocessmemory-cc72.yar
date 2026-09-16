rule TTP_XOR_WriteProcessMemory_cc72 {
  strings:
    $key_cc72 = { 9b 00 [2] a9 22 [2] af 17 [2] 81 17 [2] be 0b }

  condition:
    any of them
}