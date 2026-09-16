rule TTP_XOR_WriteProcessMemory_6ff1 {
  strings:
    $key_6ff1 = { 38 83 [2] 0a a1 [2] 0c 94 [2] 22 94 [2] 1d 88 }

  condition:
    any of them
}