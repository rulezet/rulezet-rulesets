rule TTP_XOR_WriteProcessMemory_7356 {
  strings:
    $key_7356 = { 24 24 [2] 16 06 [2] 10 33 [2] 3e 33 [2] 01 2f }

  condition:
    any of them
}