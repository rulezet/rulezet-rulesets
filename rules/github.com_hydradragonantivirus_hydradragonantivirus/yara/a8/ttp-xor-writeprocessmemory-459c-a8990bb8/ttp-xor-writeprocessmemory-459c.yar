rule TTP_XOR_WriteProcessMemory_459c {
  strings:
    $key_459c = { 12 ee [2] 20 cc [2] 26 f9 [2] 08 f9 [2] 37 e5 }

  condition:
    any of them
}