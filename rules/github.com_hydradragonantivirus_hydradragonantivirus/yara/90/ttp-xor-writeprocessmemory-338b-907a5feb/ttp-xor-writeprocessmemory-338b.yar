rule TTP_XOR_WriteProcessMemory_338b {
  strings:
    $key_338b = { 64 f9 [2] 56 db [2] 50 ee [2] 7e ee [2] 41 f2 }

  condition:
    any of them
}