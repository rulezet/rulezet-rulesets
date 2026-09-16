rule TTP_XOR_WriteProcessMemory_7ce6 {
  strings:
    $key_7ce6 = { 2b 94 [2] 19 b6 [2] 1f 83 [2] 31 83 [2] 0e 9f }

  condition:
    any of them
}