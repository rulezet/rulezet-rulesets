rule TTP_XOR_WriteProcessMemory_4161 {
  strings:
    $key_4161 = { 16 13 [2] 24 31 [2] 22 04 [2] 0c 04 [2] 33 18 }

  condition:
    any of them
}