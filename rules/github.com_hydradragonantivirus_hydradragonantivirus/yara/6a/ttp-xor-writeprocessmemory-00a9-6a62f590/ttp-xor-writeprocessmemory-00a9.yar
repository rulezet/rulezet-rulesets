rule TTP_XOR_WriteProcessMemory_00a9 {
  strings:
    $key_00a9 = { 57 db [2] 65 f9 [2] 63 cc [2] 4d cc [2] 72 d0 }

  condition:
    any of them
}