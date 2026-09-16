rule TTP_XOR_WriteProcessMemory_0e21 {
  strings:
    $key_0e21 = { 59 53 [2] 6b 71 [2] 6d 44 [2] 43 44 [2] 7c 58 }

  condition:
    any of them
}