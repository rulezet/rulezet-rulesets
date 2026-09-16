rule TTP_XOR_WriteProcessMemory_4d85 {
  strings:
    $key_4d85 = { 1a f7 [2] 28 d5 [2] 2e e0 [2] 00 e0 [2] 3f fc }

  condition:
    any of them
}