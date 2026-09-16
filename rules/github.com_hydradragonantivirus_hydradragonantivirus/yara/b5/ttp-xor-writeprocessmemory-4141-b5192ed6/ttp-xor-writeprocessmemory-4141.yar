rule TTP_XOR_WriteProcessMemory_4141 {
  strings:
    $key_4141 = { 16 33 [2] 24 11 [2] 22 24 [2] 0c 24 [2] 33 38 }

  condition:
    any of them
}