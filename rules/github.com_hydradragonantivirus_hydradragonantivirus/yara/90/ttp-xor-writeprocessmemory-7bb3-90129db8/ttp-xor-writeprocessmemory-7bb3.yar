rule TTP_XOR_WriteProcessMemory_7bb3 {
  strings:
    $key_7bb3 = { 2c c1 [2] 1e e3 [2] 18 d6 [2] 36 d6 [2] 09 ca }

  condition:
    any of them
}