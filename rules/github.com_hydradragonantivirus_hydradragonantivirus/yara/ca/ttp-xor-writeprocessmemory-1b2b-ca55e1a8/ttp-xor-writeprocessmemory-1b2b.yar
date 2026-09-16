rule TTP_XOR_WriteProcessMemory_1b2b {
  strings:
    $key_1b2b = { 4c 59 [2] 7e 7b [2] 78 4e [2] 56 4e [2] 69 52 }

  condition:
    any of them
}