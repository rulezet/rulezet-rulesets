rule TTP_XOR_WriteProcessMemory_dc92 {
  strings:
    $key_dc92 = { 8b e0 [2] b9 c2 [2] bf f7 [2] 91 f7 [2] ae eb }

  condition:
    any of them
}