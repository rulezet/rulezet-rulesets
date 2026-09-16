rule TTP_XOR_WriteProcessMemory_1900 {
  strings:
    $key_1900 = { 4e 72 [2] 7c 50 [2] 7a 65 [2] 54 65 [2] 6b 79 }

  condition:
    any of them
}