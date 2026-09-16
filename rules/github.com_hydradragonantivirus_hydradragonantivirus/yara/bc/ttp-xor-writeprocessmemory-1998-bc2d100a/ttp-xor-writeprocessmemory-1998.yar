rule TTP_XOR_WriteProcessMemory_1998 {
  strings:
    $key_1998 = { 4e ea [2] 7c c8 [2] 7a fd [2] 54 fd [2] 6b e1 }

  condition:
    any of them
}