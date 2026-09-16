rule TTP_XOR_WriteProcessMemory_0755 {
  strings:
    $key_0755 = { 50 27 [2] 62 05 [2] 64 30 [2] 4a 30 [2] 75 2c }

  condition:
    any of them
}