rule TTP_XOR_WriteProcessMemory_27a9 {
  strings:
    $key_27a9 = { 70 db [2] 42 f9 [2] 44 cc [2] 6a cc [2] 55 d0 }

  condition:
    any of them
}