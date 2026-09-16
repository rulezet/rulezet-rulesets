rule TTP_XOR_WriteProcessMemory_fba9 {
  strings:
    $key_fba9 = { ac db [2] 9e f9 [2] 98 cc [2] b6 cc [2] 89 d0 }

  condition:
    any of them
}