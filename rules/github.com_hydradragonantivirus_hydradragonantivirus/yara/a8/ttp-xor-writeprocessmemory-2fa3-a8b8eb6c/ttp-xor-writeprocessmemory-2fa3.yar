rule TTP_XOR_WriteProcessMemory_2fa3 {
  strings:
    $key_2fa3 = { 78 d1 [2] 4a f3 [2] 4c c6 [2] 62 c6 [2] 5d da }

  condition:
    any of them
}