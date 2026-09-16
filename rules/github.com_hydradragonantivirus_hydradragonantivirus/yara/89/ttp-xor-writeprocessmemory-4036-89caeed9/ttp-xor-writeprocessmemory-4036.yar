rule TTP_XOR_WriteProcessMemory_4036 {
  strings:
    $key_4036 = { 17 44 [2] 25 66 [2] 23 53 [2] 0d 53 [2] 32 4f }

  condition:
    any of them
}