rule TTP_XOR_WriteProcessMemory_61a9 {
  strings:
    $key_61a9 = { 36 db [2] 04 f9 [2] 02 cc [2] 2c cc [2] 13 d0 }

  condition:
    any of them
}