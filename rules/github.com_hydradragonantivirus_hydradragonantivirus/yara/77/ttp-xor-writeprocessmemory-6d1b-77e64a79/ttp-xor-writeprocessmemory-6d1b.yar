rule TTP_XOR_WriteProcessMemory_6d1b {
  strings:
    $key_6d1b = { 3a 69 [2] 08 4b [2] 0e 7e [2] 20 7e [2] 1f 62 }

  condition:
    any of them
}