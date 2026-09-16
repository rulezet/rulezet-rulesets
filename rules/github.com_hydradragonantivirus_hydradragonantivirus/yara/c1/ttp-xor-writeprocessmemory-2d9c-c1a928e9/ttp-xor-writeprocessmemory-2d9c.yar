rule TTP_XOR_WriteProcessMemory_2d9c {
  strings:
    $key_2d9c = { 7a ee [2] 48 cc [2] 4e f9 [2] 60 f9 [2] 5f e5 }

  condition:
    any of them
}