rule TTP_XOR_WriteProcessMemory_1e1b {
  strings:
    $key_1e1b = { 49 69 [2] 7b 4b [2] 7d 7e [2] 53 7e [2] 6c 62 }

  condition:
    any of them
}