rule TTP_XOR_WriteProcessMemory_4003 {
  strings:
    $key_4003 = { 17 71 [2] 25 53 [2] 23 66 [2] 0d 66 [2] 32 7a }

  condition:
    any of them
}