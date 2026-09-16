rule TTP_XOR_WriteProcessMemory_4bb2 {
  strings:
    $key_4bb2 = { 1c c0 [2] 2e e2 [2] 28 d7 [2] 06 d7 [2] 39 cb }

  condition:
    any of them
}