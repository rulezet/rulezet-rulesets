rule TTP_XOR_WriteProcessMemory_c453 {
  strings:
    $key_c453 = { 93 21 [2] a1 03 [2] a7 36 [2] 89 36 [2] b6 2a }

  condition:
    any of them
}