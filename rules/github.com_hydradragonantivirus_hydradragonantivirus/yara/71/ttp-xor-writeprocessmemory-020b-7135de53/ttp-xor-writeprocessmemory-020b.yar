rule TTP_XOR_WriteProcessMemory_020b {
  strings:
    $key_020b = { 55 79 [2] 67 5b [2] 61 6e [2] 4f 6e [2] 70 72 }

  condition:
    any of them
}