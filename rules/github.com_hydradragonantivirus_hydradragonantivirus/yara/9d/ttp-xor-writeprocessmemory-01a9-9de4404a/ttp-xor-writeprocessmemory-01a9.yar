rule TTP_XOR_WriteProcessMemory_01a9 {
  strings:
    $key_01a9 = { 56 db [2] 64 f9 [2] 62 cc [2] 4c cc [2] 73 d0 }

  condition:
    any of them
}