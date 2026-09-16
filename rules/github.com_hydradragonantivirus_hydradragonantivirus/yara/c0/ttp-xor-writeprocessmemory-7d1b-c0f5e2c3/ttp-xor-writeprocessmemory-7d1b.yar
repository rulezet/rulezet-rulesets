rule TTP_XOR_WriteProcessMemory_7d1b {
  strings:
    $key_7d1b = { 2a 69 [2] 18 4b [2] 1e 7e [2] 30 7e [2] 0f 62 }

  condition:
    any of them
}