rule TTP_XOR_WriteProcessMemory_5385 {
  strings:
    $key_5385 = { 04 f7 [2] 36 d5 [2] 30 e0 [2] 1e e0 [2] 21 fc }

  condition:
    any of them
}