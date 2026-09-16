rule TTP_XOR_WriteProcessMemory_5c41 {
  strings:
    $key_5c41 = { 0b 33 [2] 39 11 [2] 3f 24 [2] 11 24 [2] 2e 38 }

  condition:
    any of them
}