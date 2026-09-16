rule TTP_XOR_WriteProcessMemory_1003 {
  strings:
    $key_1003 = { 47 71 [2] 75 53 [2] 73 66 [2] 5d 66 [2] 62 7a }

  condition:
    any of them
}