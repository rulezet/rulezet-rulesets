rule TTP_XOR_WriteProcessMemory_1d9c {
  strings:
    $key_1d9c = { 4a ee [2] 78 cc [2] 7e f9 [2] 50 f9 [2] 6f e5 }

  condition:
    any of them
}