rule TTP_XOR_WriteProcessMemory_04a9 {
  strings:
    $key_04a9 = { 53 db [2] 61 f9 [2] 67 cc [2] 49 cc [2] 76 d0 }

  condition:
    any of them
}