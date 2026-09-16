rule TTP_XOR_WriteProcessMemory_6d9c {
  strings:
    $key_6d9c = { 3a ee [2] 08 cc [2] 0e f9 [2] 20 f9 [2] 1f e5 }

  condition:
    any of them
}