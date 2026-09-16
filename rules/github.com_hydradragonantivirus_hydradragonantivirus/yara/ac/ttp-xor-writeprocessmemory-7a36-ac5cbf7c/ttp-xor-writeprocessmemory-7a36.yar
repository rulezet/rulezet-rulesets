rule TTP_XOR_WriteProcessMemory_7a36 {
  strings:
    $key_7a36 = { 2d 44 [2] 1f 66 [2] 19 53 [2] 37 53 [2] 08 4f }

  condition:
    any of them
}