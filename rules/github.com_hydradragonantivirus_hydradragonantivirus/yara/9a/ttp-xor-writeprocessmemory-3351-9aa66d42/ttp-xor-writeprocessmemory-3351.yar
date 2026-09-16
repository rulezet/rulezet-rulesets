rule TTP_XOR_WriteProcessMemory_3351 {
  strings:
    $key_3351 = { 64 23 [2] 56 01 [2] 50 34 [2] 7e 34 [2] 41 28 }

  condition:
    any of them
}