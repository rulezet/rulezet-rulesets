rule TTP_XOR_WriteProcessMemory_cf96 {
  strings:
    $key_cf96 = { 98 e4 [2] aa c6 [2] ac f3 [2] 82 f3 [2] bd ef }

  condition:
    any of them
}