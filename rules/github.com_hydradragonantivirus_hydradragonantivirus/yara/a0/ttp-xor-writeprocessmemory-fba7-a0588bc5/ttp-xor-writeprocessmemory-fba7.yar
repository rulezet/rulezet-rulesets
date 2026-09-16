rule TTP_XOR_WriteProcessMemory_fba7 {
  strings:
    $key_fba7 = { ac d5 [2] 9e f7 [2] 98 c2 [2] b6 c2 [2] 89 de }

  condition:
    any of them
}