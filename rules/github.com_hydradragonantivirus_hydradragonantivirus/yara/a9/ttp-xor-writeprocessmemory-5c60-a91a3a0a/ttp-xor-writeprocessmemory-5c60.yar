rule TTP_XOR_WriteProcessMemory_5c60 {
  strings:
    $key_5c60 = { 0b 12 [2] 39 30 [2] 3f 05 [2] 11 05 [2] 2e 19 }

  condition:
    any of them
}