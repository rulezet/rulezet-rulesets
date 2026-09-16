rule TTP_XOR_WriteProcessMemory_4d9c {
  strings:
    $key_4d9c = { 1a ee [2] 28 cc [2] 2e f9 [2] 00 f9 [2] 3f e5 }

  condition:
    any of them
}