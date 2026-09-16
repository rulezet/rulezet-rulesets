rule TTP_XOR_WriteProcessMemory_4021 {
  strings:
    $key_4021 = { 17 53 [2] 25 71 [2] 23 44 [2] 0d 44 [2] 32 58 }

  condition:
    any of them
}