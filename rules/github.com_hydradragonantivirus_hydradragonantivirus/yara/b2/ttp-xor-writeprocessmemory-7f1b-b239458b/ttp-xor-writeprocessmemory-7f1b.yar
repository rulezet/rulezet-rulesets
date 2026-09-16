rule TTP_XOR_WriteProcessMemory_7f1b {
  strings:
    $key_7f1b = { 28 69 [2] 1a 4b [2] 1c 7e [2] 32 7e [2] 0d 62 }

  condition:
    any of them
}