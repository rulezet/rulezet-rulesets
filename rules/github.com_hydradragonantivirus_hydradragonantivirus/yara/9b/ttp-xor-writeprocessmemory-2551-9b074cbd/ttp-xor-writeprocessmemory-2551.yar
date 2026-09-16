rule TTP_XOR_WriteProcessMemory_2551 {
  strings:
    $key_2551 = { 72 23 [2] 40 01 [2] 46 34 [2] 68 34 [2] 57 28 }

  condition:
    any of them
}