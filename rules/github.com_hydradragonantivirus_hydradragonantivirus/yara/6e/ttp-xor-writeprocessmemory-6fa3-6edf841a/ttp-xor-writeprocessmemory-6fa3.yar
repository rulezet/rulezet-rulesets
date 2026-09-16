rule TTP_XOR_WriteProcessMemory_6fa3 {
  strings:
    $key_6fa3 = { 38 d1 [2] 0a f3 [2] 0c c6 [2] 22 c6 [2] 1d da }

  condition:
    any of them
}