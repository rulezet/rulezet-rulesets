rule TTP_XOR_WriteProcessMemory_4c2b {
  strings:
    $key_4c2b = { 1b 59 [2] 29 7b [2] 2f 4e [2] 01 4e [2] 3e 52 }

  condition:
    any of them
}