rule TTP_XOR_WriteProcessMemory_1074 {
  strings:
    $key_1074 = { 47 06 [2] 75 24 [2] 73 11 [2] 5d 11 [2] 62 0d }

  condition:
    any of them
}