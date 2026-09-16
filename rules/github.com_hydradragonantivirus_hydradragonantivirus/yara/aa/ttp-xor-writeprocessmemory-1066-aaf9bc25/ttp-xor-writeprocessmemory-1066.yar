rule TTP_XOR_WriteProcessMemory_1066 {
  strings:
    $key_1066 = { 47 14 [2] 75 36 [2] 73 03 [2] 5d 03 [2] 62 1f }

  condition:
    any of them
}