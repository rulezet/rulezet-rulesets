rule TTP_XOR_WriteProcessMemory_4b5b {
  strings:
    $key_4b5b = { 1c 29 [2] 2e 0b [2] 28 3e [2] 06 3e [2] 39 22 }

  condition:
    any of them
}