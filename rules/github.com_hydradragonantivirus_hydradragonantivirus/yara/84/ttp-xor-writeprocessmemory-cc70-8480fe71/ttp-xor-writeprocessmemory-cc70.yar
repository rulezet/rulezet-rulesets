rule TTP_XOR_WriteProcessMemory_cc70 {
  strings:
    $key_cc70 = { 9b 02 [2] a9 20 [2] af 15 [2] 81 15 [2] be 09 }

  condition:
    any of them
}