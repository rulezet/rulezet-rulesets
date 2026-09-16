rule TTP_XOR_WriteProcessMemory_6b5b {
  strings:
    $key_6b5b = { 3c 29 [2] 0e 0b [2] 08 3e [2] 26 3e [2] 19 22 }

  condition:
    any of them
}