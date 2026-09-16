rule TTP_XOR_WriteProcessMemory_cc26 {
  strings:
    $key_cc26 = { 9b 54 [2] a9 76 [2] af 43 [2] 81 43 [2] be 5f }

  condition:
    any of them
}