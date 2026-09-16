rule TTP_XOR_WriteProcessMemory_4942 {
  strings:
    $key_4942 = { 1e 30 [2] 2c 12 [2] 2a 27 [2] 04 27 [2] 3b 3b }

  condition:
    any of them
}