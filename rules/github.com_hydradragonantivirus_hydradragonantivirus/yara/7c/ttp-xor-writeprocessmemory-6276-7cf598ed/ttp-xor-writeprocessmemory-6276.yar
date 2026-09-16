rule TTP_XOR_WriteProcessMemory_6276 {
  strings:
    $key_6276 = { 35 04 [2] 07 26 [2] 01 13 [2] 2f 13 [2] 10 0f }

  condition:
    any of them
}