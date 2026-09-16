rule TTP_XOR_WriteProcessMemory_56e4 {
  strings:
    $key_56e4 = { 01 96 [2] 33 b4 [2] 35 81 [2] 1b 81 [2] 24 9d }

  condition:
    any of them
}