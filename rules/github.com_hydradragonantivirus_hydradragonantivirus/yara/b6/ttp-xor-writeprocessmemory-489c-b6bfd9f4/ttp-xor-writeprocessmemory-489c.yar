rule TTP_XOR_WriteProcessMemory_489c {
  strings:
    $key_489c = { 1f ee [2] 2d cc [2] 2b f9 [2] 05 f9 [2] 3a e5 }

  condition:
    any of them
}