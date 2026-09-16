rule TTP_XOR_WriteProcessMemory_36e6 {
  strings:
    $key_36e6 = { 61 94 [2] 53 b6 [2] 55 83 [2] 7b 83 [2] 44 9f }

  condition:
    any of them
}