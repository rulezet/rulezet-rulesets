rule TTP_XOR_WriteProcessMemory_10e6 {
  strings:
    $key_10e6 = { 47 94 [2] 75 b6 [2] 73 83 [2] 5d 83 [2] 62 9f }

  condition:
    any of them
}