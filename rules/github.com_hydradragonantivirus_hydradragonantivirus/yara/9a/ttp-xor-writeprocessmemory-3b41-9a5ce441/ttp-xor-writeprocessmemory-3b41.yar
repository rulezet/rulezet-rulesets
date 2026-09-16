rule TTP_XOR_WriteProcessMemory_3b41 {
  strings:
    $key_3b41 = { 6c 33 [2] 5e 11 [2] 58 24 [2] 76 24 [2] 49 38 }

  condition:
    any of them
}