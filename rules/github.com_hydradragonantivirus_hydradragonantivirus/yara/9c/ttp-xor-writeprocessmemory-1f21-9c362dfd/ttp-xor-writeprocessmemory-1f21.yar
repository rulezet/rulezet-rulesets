rule TTP_XOR_WriteProcessMemory_1f21 {
  strings:
    $key_1f21 = { 48 53 [2] 7a 71 [2] 7c 44 [2] 52 44 [2] 6d 58 }

  condition:
    any of them
}