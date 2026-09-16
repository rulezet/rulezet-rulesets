rule TTP_XOR_WriteProcessMemory_5d76 {
  strings:
    $key_5d76 = { 0a 04 [2] 38 26 [2] 3e 13 [2] 10 13 [2] 2f 0f }

  condition:
    any of them
}