rule TTP_XOR_WriteProcessMemory_5de4 {
  strings:
    $key_5de4 = { 0a 96 [2] 38 b4 [2] 3e 81 [2] 10 81 [2] 2f 9d }

  condition:
    any of them
}