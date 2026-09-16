rule TTP_XOR_WriteProcessMemory_eff0 {
  strings:
    $key_eff0 = { b8 82 [2] 8a a0 [2] 8c 95 [2] a2 95 [2] 9d 89 }

  condition:
    any of them
}