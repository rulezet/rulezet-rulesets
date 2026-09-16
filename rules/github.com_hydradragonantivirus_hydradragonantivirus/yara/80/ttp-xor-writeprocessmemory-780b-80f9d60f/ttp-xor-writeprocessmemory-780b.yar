rule TTP_XOR_WriteProcessMemory_780b {
  strings:
    $key_780b = { 2f 79 [2] 1d 5b [2] 1b 6e [2] 35 6e [2] 0a 72 }

  condition:
    any of them
}