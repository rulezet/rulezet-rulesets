rule TTP_XOR_WriteProcessMemory_3930 {
  strings:
    $key_3930 = { 6e 42 [2] 5c 60 [2] 5a 55 [2] 74 55 [2] 4b 49 }

  condition:
    any of them
}