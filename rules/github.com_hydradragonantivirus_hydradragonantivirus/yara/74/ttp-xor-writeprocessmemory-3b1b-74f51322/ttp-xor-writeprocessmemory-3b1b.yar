rule TTP_XOR_WriteProcessMemory_3b1b {
  strings:
    $key_3b1b = { 6c 69 [2] 5e 4b [2] 58 7e [2] 76 7e [2] 49 62 }

  condition:
    any of them
}