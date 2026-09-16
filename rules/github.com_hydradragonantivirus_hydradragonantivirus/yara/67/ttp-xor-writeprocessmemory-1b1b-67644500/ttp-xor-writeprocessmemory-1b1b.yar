rule TTP_XOR_WriteProcessMemory_1b1b {
  strings:
    $key_1b1b = { 4c 69 [2] 7e 4b [2] 78 7e [2] 56 7e [2] 69 62 }

  condition:
    any of them
}