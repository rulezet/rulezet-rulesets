rule TTP_XOR_WriteProcessMemory_1077 {
  strings:
    $key_1077 = { 47 05 [2] 75 27 [2] 73 12 [2] 5d 12 [2] 62 0e }

  condition:
    any of them
}