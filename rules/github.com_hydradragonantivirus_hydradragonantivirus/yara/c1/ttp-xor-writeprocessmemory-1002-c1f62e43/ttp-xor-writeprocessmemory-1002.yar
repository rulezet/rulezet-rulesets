rule TTP_XOR_WriteProcessMemory_1002 {
  strings:
    $key_1002 = { 47 70 [2] 75 52 [2] 73 67 [2] 5d 67 [2] 62 7b }

  condition:
    any of them
}