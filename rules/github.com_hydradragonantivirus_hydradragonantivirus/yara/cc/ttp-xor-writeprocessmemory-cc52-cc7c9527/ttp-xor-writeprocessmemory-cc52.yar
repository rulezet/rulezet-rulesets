rule TTP_XOR_WriteProcessMemory_cc52 {
  strings:
    $key_cc52 = { 9b 20 [2] a9 02 [2] af 37 [2] 81 37 [2] be 2b }

  condition:
    any of them
}