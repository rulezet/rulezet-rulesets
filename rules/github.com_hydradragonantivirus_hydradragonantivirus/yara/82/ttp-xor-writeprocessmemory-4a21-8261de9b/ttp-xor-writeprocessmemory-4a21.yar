rule TTP_XOR_WriteProcessMemory_4a21 {
  strings:
    $key_4a21 = { 1d 53 [2] 2f 71 [2] 29 44 [2] 07 44 [2] 38 58 }

  condition:
    any of them
}