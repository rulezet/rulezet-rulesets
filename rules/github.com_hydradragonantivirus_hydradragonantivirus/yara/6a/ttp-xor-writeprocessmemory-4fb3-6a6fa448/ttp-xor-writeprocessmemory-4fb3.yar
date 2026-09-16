rule TTP_XOR_WriteProcessMemory_4fb3 {
  strings:
    $key_4fb3 = { 18 c1 [2] 2a e3 [2] 2c d6 [2] 02 d6 [2] 3d ca }

  condition:
    any of them
}