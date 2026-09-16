rule TTP_XOR_WriteProcessMemory_3553 {
  strings:
    $key_3553 = { 62 21 [2] 50 03 [2] 56 36 [2] 78 36 [2] 47 2a }

  condition:
    any of them
}