rule TTP_XOR_WriteProcessMemory_6c00 {
  strings:
    $key_6c00 = { 3b 72 [2] 09 50 [2] 0f 65 [2] 21 65 [2] 1e 79 }

  condition:
    any of them
}