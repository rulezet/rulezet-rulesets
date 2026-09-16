rule TTP_XOR_WriteProcessMemory_4010 {
  strings:
    $key_4010 = { 17 62 [2] 25 40 [2] 23 75 [2] 0d 75 [2] 32 69 }

  condition:
    any of them
}