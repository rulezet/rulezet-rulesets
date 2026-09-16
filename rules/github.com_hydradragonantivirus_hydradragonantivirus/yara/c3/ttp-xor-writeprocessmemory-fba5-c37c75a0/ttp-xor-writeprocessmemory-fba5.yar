rule TTP_XOR_WriteProcessMemory_fba5 {
  strings:
    $key_fba5 = { ac d7 [2] 9e f5 [2] 98 c0 [2] b6 c0 [2] 89 dc }

  condition:
    any of them
}