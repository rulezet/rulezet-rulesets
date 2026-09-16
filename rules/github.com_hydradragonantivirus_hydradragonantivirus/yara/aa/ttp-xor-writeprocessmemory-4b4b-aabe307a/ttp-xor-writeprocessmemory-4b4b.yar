rule TTP_XOR_WriteProcessMemory_4b4b {
  strings:
    $key_4b4b = { 1c 39 [2] 2e 1b [2] 28 2e [2] 06 2e [2] 39 32 }

  condition:
    any of them
}