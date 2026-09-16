rule TTP_XOR_WriteProcessMemory_5546 {
  strings:
    $key_5546 = { 02 34 [2] 30 16 [2] 36 23 [2] 18 23 [2] 27 3f }

  condition:
    any of them
}