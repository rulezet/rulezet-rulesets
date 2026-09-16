rule TTP_XOR_WriteProcessMemory_e7c5 {
  strings:
    $key_e7c5 = { b0 b7 [2] 82 95 [2] 84 a0 [2] aa a0 [2] 95 bc }

  condition:
    any of them
}