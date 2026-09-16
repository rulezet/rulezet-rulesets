rule TTP_XOR_WriteProcessMemory_5a55 {
  strings:
    $key_5a55 = { 0d 27 [2] 3f 05 [2] 39 30 [2] 17 30 [2] 28 2c }

  condition:
    any of them
}