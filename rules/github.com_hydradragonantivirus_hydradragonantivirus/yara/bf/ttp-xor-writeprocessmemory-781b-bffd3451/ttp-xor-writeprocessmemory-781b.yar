rule TTP_XOR_WriteProcessMemory_781b {
  strings:
    $key_781b = { 2f 69 [2] 1d 4b [2] 1b 7e [2] 35 7e [2] 0a 62 }

  condition:
    any of them
}