rule TTP_XOR_WriteProcessMemory_2998 {
  strings:
    $key_2998 = { 7e ea [2] 4c c8 [2] 4a fd [2] 64 fd [2] 5b e1 }

  condition:
    any of them
}