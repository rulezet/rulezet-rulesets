rule TTP_XOR_WriteProcessMemory_4c1b {
  strings:
    $key_4c1b = { 1b 69 [2] 29 4b [2] 2f 7e [2] 01 7e [2] 3e 62 }

  condition:
    any of them
}