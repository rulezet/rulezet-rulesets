rule TTP_XOR_WriteProcessMemory_2141 {
  strings:
    $key_2141 = { 76 33 [2] 44 11 [2] 42 24 [2] 6c 24 [2] 53 38 }

  condition:
    any of them
}