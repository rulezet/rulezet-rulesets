rule TTP_XOR_WriteProcessMemory_2049 {
  strings:
    $key_2049 = { 77 3b [2] 45 19 [2] 43 2c [2] 6d 2c [2] 52 30 }

  condition:
    any of them
}