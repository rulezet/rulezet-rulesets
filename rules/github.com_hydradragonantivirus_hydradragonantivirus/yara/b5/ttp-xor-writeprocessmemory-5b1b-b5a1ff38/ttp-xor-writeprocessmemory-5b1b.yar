rule TTP_XOR_WriteProcessMemory_5b1b {
  strings:
    $key_5b1b = { 0c 69 [2] 3e 4b [2] 38 7e [2] 16 7e [2] 29 62 }

  condition:
    any of them
}