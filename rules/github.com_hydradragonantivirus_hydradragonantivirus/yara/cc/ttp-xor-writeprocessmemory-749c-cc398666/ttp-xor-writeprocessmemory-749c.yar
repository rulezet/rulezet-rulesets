rule TTP_XOR_WriteProcessMemory_749c {
  strings:
    $key_749c = { 23 ee [2] 11 cc [2] 17 f9 [2] 39 f9 [2] 06 e5 }

  condition:
    any of them
}