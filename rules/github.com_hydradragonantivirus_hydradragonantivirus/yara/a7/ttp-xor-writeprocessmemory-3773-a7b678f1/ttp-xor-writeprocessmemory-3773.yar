rule TTP_XOR_WriteProcessMemory_3773 {
  strings:
    $key_3773 = { 60 01 [2] 52 23 [2] 54 16 [2] 7a 16 [2] 45 0a }

  condition:
    any of them
}