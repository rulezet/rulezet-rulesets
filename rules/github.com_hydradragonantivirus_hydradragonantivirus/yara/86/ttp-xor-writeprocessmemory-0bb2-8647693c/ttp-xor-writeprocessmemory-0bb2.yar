rule TTP_XOR_WriteProcessMemory_0bb2 {
  strings:
    $key_0bb2 = { 5c c0 [2] 6e e2 [2] 68 d7 [2] 46 d7 [2] 79 cb }

  condition:
    any of them
}