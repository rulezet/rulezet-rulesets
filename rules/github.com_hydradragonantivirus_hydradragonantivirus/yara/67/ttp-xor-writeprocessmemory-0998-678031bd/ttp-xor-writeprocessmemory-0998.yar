rule TTP_XOR_WriteProcessMemory_0998 {
  strings:
    $key_0998 = { 5e ea [2] 6c c8 [2] 6a fd [2] 44 fd [2] 7b e1 }

  condition:
    any of them
}