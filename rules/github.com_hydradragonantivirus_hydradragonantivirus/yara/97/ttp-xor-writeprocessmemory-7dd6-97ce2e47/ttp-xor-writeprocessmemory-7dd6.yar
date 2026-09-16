rule TTP_XOR_WriteProcessMemory_7dd6 {
  strings:
    $key_7dd6 = { 2a a4 [2] 18 86 [2] 1e b3 [2] 30 b3 [2] 0f af }

  condition:
    any of them
}