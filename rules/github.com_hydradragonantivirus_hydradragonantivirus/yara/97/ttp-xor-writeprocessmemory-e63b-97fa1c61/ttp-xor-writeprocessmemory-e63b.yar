rule TTP_XOR_WriteProcessMemory_e63b {
  strings:
    $key_e63b = { b1 49 [2] 83 6b [2] 85 5e [2] ab 5e [2] 94 42 }

  condition:
    any of them
}