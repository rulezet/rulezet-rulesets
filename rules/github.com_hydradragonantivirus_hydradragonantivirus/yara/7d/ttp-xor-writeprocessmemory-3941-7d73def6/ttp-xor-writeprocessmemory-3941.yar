rule TTP_XOR_WriteProcessMemory_3941 {
  strings:
    $key_3941 = { 6e 33 [2] 5c 11 [2] 5a 24 [2] 74 24 [2] 4b 38 }

  condition:
    any of them
}