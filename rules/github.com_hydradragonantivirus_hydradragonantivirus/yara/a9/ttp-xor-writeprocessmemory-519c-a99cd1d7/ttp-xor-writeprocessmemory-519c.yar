rule TTP_XOR_WriteProcessMemory_519c {
  strings:
    $key_519c = { 06 ee [2] 34 cc [2] 32 f9 [2] 1c f9 [2] 23 e5 }

  condition:
    any of them
}