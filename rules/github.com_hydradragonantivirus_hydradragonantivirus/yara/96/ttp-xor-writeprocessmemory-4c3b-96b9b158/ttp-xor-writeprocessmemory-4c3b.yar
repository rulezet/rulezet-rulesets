rule TTP_XOR_WriteProcessMemory_4c3b {
  strings:
    $key_4c3b = { 1b 49 [2] 29 6b [2] 2f 5e [2] 01 5e [2] 3e 42 }

  condition:
    any of them
}