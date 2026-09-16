rule TTP_XOR_WriteProcessMemory_4100 {
  strings:
    $key_4100 = { 16 72 [2] 24 50 [2] 22 65 [2] 0c 65 [2] 33 79 }

  condition:
    any of them
}