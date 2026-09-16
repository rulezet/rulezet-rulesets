rule TTP_XOR_WriteProcessMemory_26a9 {
  strings:
    $key_26a9 = { 71 db [2] 43 f9 [2] 45 cc [2] 6b cc [2] 54 d0 }

  condition:
    any of them
}