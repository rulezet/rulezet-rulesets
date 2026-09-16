rule TTP_XOR_WriteProcessMemory_6d85 {
  strings:
    $key_6d85 = { 3a f7 [2] 08 d5 [2] 0e e0 [2] 20 e0 [2] 1f fc }

  condition:
    any of them
}