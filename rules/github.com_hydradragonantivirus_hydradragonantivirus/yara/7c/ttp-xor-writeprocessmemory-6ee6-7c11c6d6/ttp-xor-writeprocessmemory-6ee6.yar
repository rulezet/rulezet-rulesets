rule TTP_XOR_WriteProcessMemory_6ee6 {
  strings:
    $key_6ee6 = { 39 94 [2] 0b b6 [2] 0d 83 [2] 23 83 [2] 1c 9f }

  condition:
    any of them
}