rule TTP_XOR_WriteProcessMemory_175b {
  strings:
    $key_175b = { 40 29 [2] 72 0b [2] 74 3e [2] 5a 3e [2] 65 22 }

  condition:
    any of them
}