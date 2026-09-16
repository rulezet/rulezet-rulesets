rule TTP_XOR_WriteProcessMemory_4998 {
  strings:
    $key_4998 = { 1e ea [2] 2c c8 [2] 2a fd [2] 04 fd [2] 3b e1 }

  condition:
    any of them
}