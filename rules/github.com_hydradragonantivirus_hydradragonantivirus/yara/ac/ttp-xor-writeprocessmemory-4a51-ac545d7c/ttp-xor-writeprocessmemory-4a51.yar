rule TTP_XOR_WriteProcessMemory_4a51 {
  strings:
    $key_4a51 = { 1d 23 [2] 2f 01 [2] 29 34 [2] 07 34 [2] 38 28 }

  condition:
    any of them
}