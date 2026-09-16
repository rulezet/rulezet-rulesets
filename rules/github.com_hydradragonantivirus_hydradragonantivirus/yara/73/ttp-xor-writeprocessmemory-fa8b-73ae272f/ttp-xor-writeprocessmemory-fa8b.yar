rule TTP_XOR_WriteProcessMemory_fa8b {
  strings:
    $key_fa8b = { ad f9 [2] 9f db [2] 99 ee [2] b7 ee [2] 88 f2 }

  condition:
    any of them
}