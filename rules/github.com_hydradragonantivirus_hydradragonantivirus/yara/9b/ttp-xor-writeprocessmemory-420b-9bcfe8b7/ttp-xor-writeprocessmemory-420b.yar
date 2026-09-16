rule TTP_XOR_WriteProcessMemory_420b {
  strings:
    $key_420b = { 15 79 [2] 27 5b [2] 21 6e [2] 0f 6e [2] 30 72 }

  condition:
    any of them
}