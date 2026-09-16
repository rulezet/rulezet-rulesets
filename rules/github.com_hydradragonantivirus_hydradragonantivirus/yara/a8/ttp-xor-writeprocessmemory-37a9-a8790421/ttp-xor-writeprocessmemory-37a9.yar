rule TTP_XOR_WriteProcessMemory_37a9 {
  strings:
    $key_37a9 = { 60 db [2] 52 f9 [2] 54 cc [2] 7a cc [2] 45 d0 }

  condition:
    any of them
}