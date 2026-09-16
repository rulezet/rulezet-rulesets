rule TTP_XOR_WriteProcessMemory_1c2b {
  strings:
    $key_1c2b = { 4b 59 [2] 79 7b [2] 7f 4e [2] 51 4e [2] 6e 52 }

  condition:
    any of them
}