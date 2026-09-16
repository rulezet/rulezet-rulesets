rule TTP_XOR_WriteProcessMemory_2040 {
  strings:
    $key_2040 = { 77 32 [2] 45 10 [2] 43 25 [2] 6d 25 [2] 52 39 }

  condition:
    any of them
}