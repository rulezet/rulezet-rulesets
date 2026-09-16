rule TTP_XOR_WriteProcessMemory_149c {
  strings:
    $key_149c = { 43 ee [2] 71 cc [2] 77 f9 [2] 59 f9 [2] 66 e5 }

  condition:
    any of them
}