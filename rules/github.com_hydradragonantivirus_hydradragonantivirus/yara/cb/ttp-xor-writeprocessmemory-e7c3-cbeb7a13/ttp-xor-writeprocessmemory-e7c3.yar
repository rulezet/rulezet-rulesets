rule TTP_XOR_WriteProcessMemory_e7c3 {
  strings:
    $key_e7c3 = { b0 b1 [2] 82 93 [2] 84 a6 [2] aa a6 [2] 95 ba }

  condition:
    any of them
}