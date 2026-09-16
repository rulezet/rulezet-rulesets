rule TTP_XOR_WriteProcessMemory_1053 {
  strings:
    $key_1053 = { 47 21 [2] 75 03 [2] 73 36 [2] 5d 36 [2] 62 2a }

  condition:
    any of them
}