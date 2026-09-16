rule TTP_XOR_WriteProcessMemory_4160 {
  strings:
    $key_4160 = { 16 12 [2] 24 30 [2] 22 05 [2] 0c 05 [2] 33 19 }

  condition:
    any of them
}