rule TTP_XOR_WriteProcessMemory_7bb5 {
  strings:
    $key_7bb5 = { 2c c7 [2] 1e e5 [2] 18 d0 [2] 36 d0 [2] 09 cc }

  condition:
    any of them
}