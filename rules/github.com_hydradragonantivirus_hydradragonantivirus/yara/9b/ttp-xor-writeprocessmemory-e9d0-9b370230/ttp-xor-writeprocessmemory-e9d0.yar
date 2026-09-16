rule TTP_XOR_WriteProcessMemory_e9d0 {
  strings:
    $key_e9d0 = { be a2 [2] 8c 80 [2] 8a b5 [2] a4 b5 [2] 9b a9 }

  condition:
    any of them
}