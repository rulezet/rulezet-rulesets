rule TTP_XOR_WriteProcessMemory_e5c5 {
  strings:
    $key_e5c5 = { b2 b7 [2] 80 95 [2] 86 a0 [2] a8 a0 [2] 97 bc }

  condition:
    any of them
}