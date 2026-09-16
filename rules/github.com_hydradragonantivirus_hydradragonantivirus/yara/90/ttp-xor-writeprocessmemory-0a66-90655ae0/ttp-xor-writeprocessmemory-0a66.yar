rule TTP_XOR_WriteProcessMemory_0a66 {
  strings:
    $key_0a66 = { 5d 14 [2] 6f 36 [2] 69 03 [2] 47 03 [2] 78 1f }

  condition:
    any of them
}