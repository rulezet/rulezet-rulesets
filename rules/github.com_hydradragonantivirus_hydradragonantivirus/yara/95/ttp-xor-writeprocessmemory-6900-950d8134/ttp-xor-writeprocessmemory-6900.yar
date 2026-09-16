rule TTP_XOR_WriteProcessMemory_6900 {
  strings:
    $key_6900 = { 3e 72 [2] 0c 50 [2] 0a 65 [2] 24 65 [2] 1b 79 }

  condition:
    any of them
}