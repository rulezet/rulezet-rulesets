rule TTP_XOR_WriteProcessMemory_4a36 {
  strings:
    $key_4a36 = { 1d 44 [2] 2f 66 [2] 29 53 [2] 07 53 [2] 38 4f }

  condition:
    any of them
}