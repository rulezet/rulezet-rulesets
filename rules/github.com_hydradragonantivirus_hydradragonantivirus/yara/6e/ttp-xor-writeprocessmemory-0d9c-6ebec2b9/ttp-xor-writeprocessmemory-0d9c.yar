rule TTP_XOR_WriteProcessMemory_0d9c {
  strings:
    $key_0d9c = { 5a ee [2] 68 cc [2] 6e f9 [2] 40 f9 [2] 7f e5 }

  condition:
    any of them
}