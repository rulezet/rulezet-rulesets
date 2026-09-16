rule TTP_XOR_WriteProcessMemory_548b {
  strings:
    $key_548b = { 03 f9 [2] 31 db [2] 37 ee [2] 19 ee [2] 26 f2 }

  condition:
    any of them
}