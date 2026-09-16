rule TTP_XOR_WriteProcessMemory_7a66 {
  strings:
    $key_7a66 = { 2d 14 [2] 1f 36 [2] 19 03 [2] 37 03 [2] 08 1f }

  condition:
    any of them
}