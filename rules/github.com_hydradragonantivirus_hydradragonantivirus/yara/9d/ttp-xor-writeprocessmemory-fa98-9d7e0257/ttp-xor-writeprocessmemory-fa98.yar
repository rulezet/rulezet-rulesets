rule TTP_XOR_WriteProcessMemory_fa98 {
  strings:
    $key_fa98 = { ad ea [2] 9f c8 [2] 99 fd [2] b7 fd [2] 88 e1 }

  condition:
    any of them
}