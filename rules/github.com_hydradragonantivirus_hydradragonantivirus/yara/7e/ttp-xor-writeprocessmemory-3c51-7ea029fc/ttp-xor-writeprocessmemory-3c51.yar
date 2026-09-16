rule TTP_XOR_WriteProcessMemory_3c51 {
  strings:
    $key_3c51 = { 6b 23 [2] 59 01 [2] 5f 34 [2] 71 34 [2] 4e 28 }

  condition:
    any of them
}