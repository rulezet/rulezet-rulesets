rule TTP_XOR_WriteProcessMemory_e7c4 {
  strings:
    $key_e7c4 = { b0 b6 [2] 82 94 [2] 84 a1 [2] aa a1 [2] 95 bd }

  condition:
    any of them
}