rule TTP_XOR_WriteProcessMemory_0f87 {
  strings:
    $key_0f87 = { 58 f5 [2] 6a d7 [2] 6c e2 [2] 42 e2 [2] 7d fe }

  condition:
    any of them
}