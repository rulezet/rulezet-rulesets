rule TTP_XOR_WriteProcessMemory_10a9 {
  strings:
    $key_10a9 = { 47 db [2] 75 f9 [2] 73 cc [2] 5d cc [2] 62 d0 }

  condition:
    any of them
}