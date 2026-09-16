rule TTP_XOR_WriteProcessMemory_e6a9 {
  strings:
    $key_e6a9 = { b1 db [2] 83 f9 [2] 85 cc [2] ab cc [2] 94 d0 }

  condition:
    any of them
}