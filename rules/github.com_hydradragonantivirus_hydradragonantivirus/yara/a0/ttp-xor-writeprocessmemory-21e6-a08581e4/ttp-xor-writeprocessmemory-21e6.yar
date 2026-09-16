rule TTP_XOR_WriteProcessMemory_21e6 {
  strings:
    $key_21e6 = { 76 94 [2] 44 b6 [2] 42 83 [2] 6c 83 [2] 53 9f }

  condition:
    any of them
}