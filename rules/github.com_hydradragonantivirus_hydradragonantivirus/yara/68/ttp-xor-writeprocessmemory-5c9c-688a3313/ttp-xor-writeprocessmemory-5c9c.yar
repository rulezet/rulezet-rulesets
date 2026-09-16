rule TTP_XOR_WriteProcessMemory_5c9c {
  strings:
    $key_5c9c = { 0b ee [2] 39 cc [2] 3f f9 [2] 11 f9 [2] 2e e5 }

  condition:
    any of them
}