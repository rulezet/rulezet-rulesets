rule TTP_XOR_WriteProcessMemory_7553 {
  strings:
    $key_7553 = { 22 21 [2] 10 03 [2] 16 36 [2] 38 36 [2] 07 2a }

  condition:
    any of them
}