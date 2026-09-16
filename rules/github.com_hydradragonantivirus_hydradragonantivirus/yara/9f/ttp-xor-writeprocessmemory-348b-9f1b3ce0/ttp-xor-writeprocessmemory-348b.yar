rule TTP_XOR_WriteProcessMemory_348b {
  strings:
    $key_348b = { 63 f9 [2] 51 db [2] 57 ee [2] 79 ee [2] 46 f2 }

  condition:
    any of them
}