rule TTP_XOR_WriteProcessMemory_cc32 {
  strings:
    $key_cc32 = { 9b 40 [2] a9 62 [2] af 57 [2] 81 57 [2] be 4b }

  condition:
    any of them
}