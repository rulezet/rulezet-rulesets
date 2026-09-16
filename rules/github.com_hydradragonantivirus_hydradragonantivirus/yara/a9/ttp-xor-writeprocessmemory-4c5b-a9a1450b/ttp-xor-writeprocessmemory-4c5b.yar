rule TTP_XOR_WriteProcessMemory_4c5b {
  strings:
    $key_4c5b = { 1b 29 [2] 29 0b [2] 2f 3e [2] 01 3e [2] 3e 22 }

  condition:
    any of them
}