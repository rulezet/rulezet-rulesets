rule TTP_XOR_WriteProcessMemory_40f8 {
  strings:
    $key_40f8 = { 17 8a [2] 25 a8 [2] 23 9d [2] 0d 9d [2] 32 81 }

  condition:
    any of them
}