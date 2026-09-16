rule TTP_XOR_WriteProcessMemory_4aa9 {
  strings:
    $key_4aa9 = { 1d db [2] 2f f9 [2] 29 cc [2] 07 cc [2] 38 d0 }

  condition:
    any of them
}