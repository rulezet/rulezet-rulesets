rule TTP_XOR_WriteProcessMemory_5d85 {
  strings:
    $key_5d85 = { 0a f7 [2] 38 d5 [2] 3e e0 [2] 10 e0 [2] 2f fc }

  condition:
    any of them
}