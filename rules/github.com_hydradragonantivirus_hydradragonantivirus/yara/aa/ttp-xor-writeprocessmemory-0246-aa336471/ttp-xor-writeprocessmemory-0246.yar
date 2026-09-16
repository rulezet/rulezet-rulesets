rule TTP_XOR_WriteProcessMemory_0246 {
  strings:
    $key_0246 = { 55 34 [2] 67 16 [2] 61 23 [2] 4f 23 [2] 70 3f }

  condition:
    any of them
}