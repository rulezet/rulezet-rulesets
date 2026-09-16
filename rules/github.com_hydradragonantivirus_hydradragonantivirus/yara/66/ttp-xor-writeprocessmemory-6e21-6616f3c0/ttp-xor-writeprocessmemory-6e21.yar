rule TTP_XOR_WriteProcessMemory_6e21 {
  strings:
    $key_6e21 = { 39 53 [2] 0b 71 [2] 0d 44 [2] 23 44 [2] 1c 58 }

  condition:
    any of them
}