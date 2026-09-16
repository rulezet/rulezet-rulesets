rule TTP_XOR_WriteProcessMemory_5d9c {
  strings:
    $key_5d9c = { 0a ee [2] 38 cc [2] 3e f9 [2] 10 f9 [2] 2f e5 }

  condition:
    any of them
}