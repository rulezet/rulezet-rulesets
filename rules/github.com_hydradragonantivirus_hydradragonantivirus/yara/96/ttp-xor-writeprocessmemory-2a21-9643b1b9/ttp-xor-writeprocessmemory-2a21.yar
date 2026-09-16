rule TTP_XOR_WriteProcessMemory_2a21 {
  strings:
    $key_2a21 = { 7d 53 [2] 4f 71 [2] 49 44 [2] 67 44 [2] 58 58 }

  condition:
    any of them
}