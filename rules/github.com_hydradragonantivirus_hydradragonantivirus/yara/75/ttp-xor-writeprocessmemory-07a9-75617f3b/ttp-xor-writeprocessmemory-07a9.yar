rule TTP_XOR_WriteProcessMemory_07a9 {
  strings:
    $key_07a9 = { 50 db [2] 62 f9 [2] 64 cc [2] 4a cc [2] 75 d0 }

  condition:
    any of them
}