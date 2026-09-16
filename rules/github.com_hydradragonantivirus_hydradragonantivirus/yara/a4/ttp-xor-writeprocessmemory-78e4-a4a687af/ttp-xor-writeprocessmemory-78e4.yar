rule TTP_XOR_WriteProcessMemory_78e4 {
  strings:
    $key_78e4 = { 2f 96 [2] 1d b4 [2] 1b 81 [2] 35 81 [2] 0a 9d }

  condition:
    any of them
}