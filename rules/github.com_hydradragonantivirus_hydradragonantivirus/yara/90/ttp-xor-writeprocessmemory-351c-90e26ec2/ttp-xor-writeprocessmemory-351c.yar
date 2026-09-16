rule TTP_XOR_WriteProcessMemory_351c {
  strings:
    $key_351c = { 62 6e [2] 50 4c [2] 56 79 [2] 78 79 [2] 47 65 }

  condition:
    any of them
}