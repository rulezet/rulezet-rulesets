rule TTP_XOR_WriteProcessMemory_3851 {
  strings:
    $key_3851 = { 6f 23 [2] 5d 01 [2] 5b 34 [2] 75 34 [2] 4a 28 }

  condition:
    any of them
}