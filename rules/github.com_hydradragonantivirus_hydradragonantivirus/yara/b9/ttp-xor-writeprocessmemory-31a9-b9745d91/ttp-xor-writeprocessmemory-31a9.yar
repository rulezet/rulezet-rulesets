rule TTP_XOR_WriteProcessMemory_31a9 {
  strings:
    $key_31a9 = { 66 db [2] 54 f9 [2] 52 cc [2] 7c cc [2] 43 d0 }

  condition:
    any of them
}