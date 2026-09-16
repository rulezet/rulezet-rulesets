rule TTP_XOR_WriteProcessMemory_e6d2 {
  strings:
    $key_e6d2 = { b1 a0 [2] 83 82 [2] 85 b7 [2] ab b7 [2] 94 ab }

  condition:
    any of them
}