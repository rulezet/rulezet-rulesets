rule TTP_XOR_WriteProcessMemory_5f87 {
  strings:
    $key_5f87 = { 08 f5 [2] 3a d7 [2] 3c e2 [2] 12 e2 [2] 2d fe }

  condition:
    any of them
}