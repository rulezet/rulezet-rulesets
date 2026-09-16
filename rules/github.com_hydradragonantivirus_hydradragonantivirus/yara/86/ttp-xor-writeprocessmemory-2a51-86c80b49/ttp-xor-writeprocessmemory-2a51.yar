rule TTP_XOR_WriteProcessMemory_2a51 {
  strings:
    $key_2a51 = { 7d 23 [2] 4f 01 [2] 49 34 [2] 67 34 [2] 58 28 }

  condition:
    any of them
}