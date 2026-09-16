rule TTP_XOR_WriteProcessMemory_41a9 {
  strings:
    $key_41a9 = { 16 db [2] 24 f9 [2] 22 cc [2] 0c cc [2] 33 d0 }

  condition:
    any of them
}