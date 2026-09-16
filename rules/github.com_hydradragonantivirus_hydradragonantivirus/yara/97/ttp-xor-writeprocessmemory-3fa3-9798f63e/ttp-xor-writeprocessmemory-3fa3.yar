rule TTP_XOR_WriteProcessMemory_3fa3 {
  strings:
    $key_3fa3 = { 68 d1 [2] 5a f3 [2] 5c c6 [2] 72 c6 [2] 4d da }

  condition:
    any of them
}