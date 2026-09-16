rule TTP_XOR_WriteProcessMemory_38e6 {
  strings:
    $key_38e6 = { 6f 94 [2] 5d b6 [2] 5b 83 [2] 75 83 [2] 4a 9f }

  condition:
    any of them
}