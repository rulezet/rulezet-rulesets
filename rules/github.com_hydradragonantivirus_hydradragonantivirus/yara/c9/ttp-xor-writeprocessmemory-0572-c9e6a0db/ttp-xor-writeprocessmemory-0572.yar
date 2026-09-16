rule TTP_XOR_WriteProcessMemory_0572 {
  strings:
    $key_0572 = { 52 00 [2] 60 22 [2] 66 17 [2] 48 17 [2] 77 0b }

  condition:
    any of them
}