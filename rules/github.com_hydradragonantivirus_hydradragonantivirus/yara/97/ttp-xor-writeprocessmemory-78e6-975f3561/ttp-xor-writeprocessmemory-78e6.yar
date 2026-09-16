rule TTP_XOR_WriteProcessMemory_78e6 {
  strings:
    $key_78e6 = { 2f 94 [2] 1d b6 [2] 1b 83 [2] 35 83 [2] 0a 9f }

  condition:
    any of them
}