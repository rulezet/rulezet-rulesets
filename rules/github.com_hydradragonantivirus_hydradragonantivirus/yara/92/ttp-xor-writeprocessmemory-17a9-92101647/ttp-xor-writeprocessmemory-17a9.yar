rule TTP_XOR_WriteProcessMemory_17a9 {
  strings:
    $key_17a9 = { 40 db [2] 72 f9 [2] 74 cc [2] 5a cc [2] 65 d0 }

  condition:
    any of them
}