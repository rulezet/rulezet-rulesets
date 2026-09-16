rule TTP_XOR_WriteProcessMemory_34a9 {
  strings:
    $key_34a9 = { 63 db [2] 51 f9 [2] 57 cc [2] 79 cc [2] 46 d0 }

  condition:
    any of them
}