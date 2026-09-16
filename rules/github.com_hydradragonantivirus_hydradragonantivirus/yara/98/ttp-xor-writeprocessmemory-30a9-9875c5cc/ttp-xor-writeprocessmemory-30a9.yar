rule TTP_XOR_WriteProcessMemory_30a9 {
  strings:
    $key_30a9 = { 67 db [2] 55 f9 [2] 53 cc [2] 7d cc [2] 42 d0 }

  condition:
    any of them
}