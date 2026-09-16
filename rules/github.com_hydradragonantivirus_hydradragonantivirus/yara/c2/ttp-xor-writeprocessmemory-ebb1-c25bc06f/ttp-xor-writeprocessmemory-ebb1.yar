rule TTP_XOR_WriteProcessMemory_ebb1 {
  strings:
    $key_ebb1 = { bc c3 [2] 8e e1 [2] 88 d4 [2] a6 d4 [2] 99 c8 }

  condition:
    any of them
}