rule TTP_XOR_WriteProcessMemory_7fa3 {
  strings:
    $key_7fa3 = { 28 d1 [2] 1a f3 [2] 1c c6 [2] 32 c6 [2] 0d da }

  condition:
    any of them
}