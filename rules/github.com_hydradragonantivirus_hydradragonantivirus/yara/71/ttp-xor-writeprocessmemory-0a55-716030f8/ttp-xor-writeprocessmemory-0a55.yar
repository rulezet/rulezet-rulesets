rule TTP_XOR_WriteProcessMemory_0a55 {
  strings:
    $key_0a55 = { 5d 27 [2] 6f 05 [2] 69 30 [2] 47 30 [2] 78 2c }

  condition:
    any of them
}