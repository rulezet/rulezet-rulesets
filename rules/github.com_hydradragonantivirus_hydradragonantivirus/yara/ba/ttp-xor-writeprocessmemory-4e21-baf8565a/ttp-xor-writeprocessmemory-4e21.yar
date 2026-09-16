rule TTP_XOR_WriteProcessMemory_4e21 {
  strings:
    $key_4e21 = { 19 53 [2] 2b 71 [2] 2d 44 [2] 03 44 [2] 3c 58 }

  condition:
    any of them
}