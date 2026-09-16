rule TTP_XOR_WriteProcessMemory_49cc {
  strings:
    $key_49cc = { 1e be [2] 2c 9c [2] 2a a9 [2] 04 a9 [2] 3b b5 }

  condition:
    any of them
}