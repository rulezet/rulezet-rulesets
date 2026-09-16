rule TTP_XOR_WriteProcessMemory_efc2 {
  strings:
    $key_efc2 = { b8 b0 [2] 8a 92 [2] 8c a7 [2] a2 a7 [2] 9d bb }

  condition:
    any of them
}