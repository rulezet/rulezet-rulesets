rule TTP_XOR_WriteProcessMemory_fba0 {
  strings:
    $key_fba0 = { ac d2 [2] 9e f0 [2] 98 c5 [2] b6 c5 [2] 89 d9 }

  condition:
    any of them
}