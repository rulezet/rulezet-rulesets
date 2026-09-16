rule TTP_XOR_WriteProcessMemory_e982 {
  strings:
    $key_e982 = { be f0 [2] 8c d2 [2] 8a e7 [2] a4 e7 [2] 9b fb }

  condition:
    any of them
}