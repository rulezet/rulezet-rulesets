rule TTP_XOR_WriteProcessMemory_cc60 {
  strings:
    $key_cc60 = { 9b 12 [2] a9 30 [2] af 05 [2] 81 05 [2] be 19 }

  condition:
    any of them
}