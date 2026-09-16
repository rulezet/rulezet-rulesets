rule TTP_XOR_WriteProcessMemory_4038 {
  strings:
    $key_4038 = { 17 4a [2] 25 68 [2] 23 5d [2] 0d 5d [2] 32 41 }

  condition:
    any of them
}