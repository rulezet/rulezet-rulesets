rule TTP_XOR_WriteProcessMemory_4b3b {
  strings:
    $key_4b3b = { 1c 49 [2] 2e 6b [2] 28 5e [2] 06 5e [2] 39 42 }

  condition:
    any of them
}