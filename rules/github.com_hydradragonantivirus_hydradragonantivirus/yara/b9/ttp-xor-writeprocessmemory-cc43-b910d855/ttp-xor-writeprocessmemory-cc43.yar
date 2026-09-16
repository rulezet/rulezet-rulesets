rule TTP_XOR_WriteProcessMemory_cc43 {
  strings:
    $key_cc43 = { 9b 31 [2] a9 13 [2] af 26 [2] 81 26 [2] be 3a }

  condition:
    any of them
}