rule TTP_XOR_WriteProcessMemory_349c {
  strings:
    $key_349c = { 63 ee [2] 51 cc [2] 57 f9 [2] 79 f9 [2] 46 e5 }

  condition:
    any of them
}