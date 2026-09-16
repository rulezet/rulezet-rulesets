rule TTP_XOR_WriteProcessMemory_3c10 {
  strings:
    $key_3c10 = { 6b 62 [2] 59 40 [2] 5f 75 [2] 71 75 [2] 4e 69 }

  condition:
    any of them
}