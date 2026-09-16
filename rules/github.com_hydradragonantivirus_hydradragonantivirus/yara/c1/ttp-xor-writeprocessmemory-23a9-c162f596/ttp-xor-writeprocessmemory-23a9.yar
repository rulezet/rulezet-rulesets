rule TTP_XOR_WriteProcessMemory_23a9 {
  strings:
    $key_23a9 = { 74 db [2] 46 f9 [2] 40 cc [2] 6e cc [2] 51 d0 }

  condition:
    any of them
}