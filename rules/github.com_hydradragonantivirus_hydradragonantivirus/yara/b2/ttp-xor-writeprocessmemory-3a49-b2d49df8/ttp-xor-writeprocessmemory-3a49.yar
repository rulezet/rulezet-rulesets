rule TTP_XOR_WriteProcessMemory_3a49 {
  strings:
    $key_3a49 = { 6d 3b [2] 5f 19 [2] 59 2c [2] 77 2c [2] 48 30 }

  condition:
    any of them
}