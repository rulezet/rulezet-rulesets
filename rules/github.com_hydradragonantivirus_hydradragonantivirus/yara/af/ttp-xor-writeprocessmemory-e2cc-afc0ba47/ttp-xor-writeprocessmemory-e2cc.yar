rule TTP_XOR_WriteProcessMemory_e2cc {
  strings:
    $key_e2cc = { b5 be [2] 87 9c [2] 81 a9 [2] af a9 [2] 90 b5 }

  condition:
    any of them
}