rule TTP_XOR_WriteProcessMemory_efa3 {
  strings:
    $key_efa3 = { b8 d1 [2] 8a f3 [2] 8c c6 [2] a2 c6 [2] 9d da }

  condition:
    any of them
}