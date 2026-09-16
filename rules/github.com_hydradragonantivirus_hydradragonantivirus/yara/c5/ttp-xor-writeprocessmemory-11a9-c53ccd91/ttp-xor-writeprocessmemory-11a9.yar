rule TTP_XOR_WriteProcessMemory_11a9 {
  strings:
    $key_11a9 = { 46 db [2] 74 f9 [2] 72 cc [2] 5c cc [2] 63 d0 }

  condition:
    any of them
}