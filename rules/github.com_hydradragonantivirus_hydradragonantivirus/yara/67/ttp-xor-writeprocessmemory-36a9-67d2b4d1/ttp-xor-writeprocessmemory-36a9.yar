rule TTP_XOR_WriteProcessMemory_36a9 {
  strings:
    $key_36a9 = { 61 db [2] 53 f9 [2] 55 cc [2] 7b cc [2] 44 d0 }

  condition:
    any of them
}