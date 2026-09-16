rule TTP_XOR_WriteProcessMemory_0c4b {
  strings:
    $key_0c4b = { 5b 39 [2] 69 1b [2] 6f 2e [2] 41 2e [2] 7e 32 }

  condition:
    any of them
}