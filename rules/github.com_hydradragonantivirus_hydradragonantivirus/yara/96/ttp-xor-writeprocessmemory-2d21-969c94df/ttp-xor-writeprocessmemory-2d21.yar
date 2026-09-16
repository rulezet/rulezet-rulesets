rule TTP_XOR_WriteProcessMemory_2d21 {
  strings:
    $key_2d21 = { 7a 53 [2] 48 71 [2] 4e 44 [2] 60 44 [2] 5f 58 }

  condition:
    any of them
}