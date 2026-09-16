rule TTP_XOR_WriteProcessMemory_5d1b {
  strings:
    $key_5d1b = { 0a 69 [2] 38 4b [2] 3e 7e [2] 10 7e [2] 2f 62 }

  condition:
    any of them
}