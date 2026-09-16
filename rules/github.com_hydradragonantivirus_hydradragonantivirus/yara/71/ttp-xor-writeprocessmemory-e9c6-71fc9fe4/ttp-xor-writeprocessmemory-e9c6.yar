rule TTP_XOR_WriteProcessMemory_e9c6 {
  strings:
    $key_e9c6 = { be b4 [2] 8c 96 [2] 8a a3 [2] a4 a3 [2] 9b bf }

  condition:
    any of them
}