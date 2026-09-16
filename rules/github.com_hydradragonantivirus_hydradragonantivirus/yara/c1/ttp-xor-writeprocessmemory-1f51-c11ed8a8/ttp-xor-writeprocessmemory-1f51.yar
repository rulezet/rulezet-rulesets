rule TTP_XOR_WriteProcessMemory_1f51 {
  strings:
    $key_1f51 = { 48 23 [2] 7a 01 [2] 7c 34 [2] 52 34 [2] 6d 28 }

  condition:
    any of them
}