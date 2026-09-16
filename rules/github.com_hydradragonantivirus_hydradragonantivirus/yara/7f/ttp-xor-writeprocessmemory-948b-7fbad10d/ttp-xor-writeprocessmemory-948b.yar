rule TTP_XOR_WriteProcessMemory_948b {
  strings:
    $key_948b = { c3 f9 [2] f1 db [2] f7 ee [2] d9 ee [2] e6 f2 }

  condition:
    any of them
}