rule TTP_XOR_WriteProcessMemory_5187 {
  strings:
    $key_5187 = { 06 f5 [2] 34 d7 [2] 32 e2 [2] 1c e2 [2] 23 fe }

  condition:
    any of them
}