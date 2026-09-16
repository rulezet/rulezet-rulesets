rule TTP_XOR_WriteProcessMemory_6d76 {
  strings:
    $key_6d76 = { 3a 04 [2] 08 26 [2] 0e 13 [2] 20 13 [2] 1f 0f }

  condition:
    any of them
}