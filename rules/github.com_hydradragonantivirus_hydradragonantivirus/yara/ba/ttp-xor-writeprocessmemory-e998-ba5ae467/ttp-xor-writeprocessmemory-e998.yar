rule TTP_XOR_WriteProcessMemory_e998 {
  strings:
    $key_e998 = { be ea [2] 8c c8 [2] 8a fd [2] a4 fd [2] 9b e1 }

  condition:
    any of them
}