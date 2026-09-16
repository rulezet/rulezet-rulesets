rule TTP_XOR_WriteProcessMemory_e9d1 {
  strings:
    $key_e9d1 = { be a3 [2] 8c 81 [2] 8a b4 [2] a4 b4 [2] 9b a8 }

  condition:
    any of them
}