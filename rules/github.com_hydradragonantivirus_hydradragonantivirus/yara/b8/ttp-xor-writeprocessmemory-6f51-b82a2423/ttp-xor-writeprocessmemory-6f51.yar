rule TTP_XOR_WriteProcessMemory_6f51 {
  strings:
    $key_6f51 = { 38 23 [2] 0a 01 [2] 0c 34 [2] 22 34 [2] 1d 28 }

  condition:
    any of them
}