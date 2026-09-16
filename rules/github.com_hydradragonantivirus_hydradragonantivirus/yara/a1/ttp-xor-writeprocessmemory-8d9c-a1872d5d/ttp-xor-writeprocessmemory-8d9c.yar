rule TTP_XOR_WriteProcessMemory_8d9c {
  strings:
    $key_8d9c = { da ee [2] e8 cc [2] ee f9 [2] c0 f9 [2] ff e5 }

  condition:
    any of them
}