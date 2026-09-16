rule TTP_XOR_WriteProcessMemory_538b {
  strings:
    $key_538b = { 04 f9 [2] 36 db [2] 30 ee [2] 1e ee [2] 21 f2 }

  condition:
    any of them
}