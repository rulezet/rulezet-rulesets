rule TTP_XOR_WriteProcessMemory_ed81 {
  strings:
    $key_ed81 = { ba f3 [2] 88 d1 [2] 8e e4 [2] a0 e4 [2] 9f f8 }

  condition:
    any of them
}