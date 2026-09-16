rule TTP_XOR_WriteProcessMemory_7387 {
  strings:
    $key_7387 = { 24 f5 [2] 16 d7 [2] 10 e2 [2] 3e e2 [2] 01 fe }

  condition:
    any of them
}