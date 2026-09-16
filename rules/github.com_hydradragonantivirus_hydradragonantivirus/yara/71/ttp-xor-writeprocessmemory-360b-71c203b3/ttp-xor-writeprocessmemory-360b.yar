rule TTP_XOR_WriteProcessMemory_360b {
  strings:
    $key_360b = { 61 79 [2] 53 5b [2] 55 6e [2] 7b 6e [2] 44 72 }

  condition:
    any of them
}