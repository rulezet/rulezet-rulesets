rule TTP_XOR_WriteProcessMemory_4821 {
  strings:
    $key_4821 = { 1f 53 [2] 2d 71 [2] 2b 44 [2] 05 44 [2] 3a 58 }

  condition:
    any of them
}