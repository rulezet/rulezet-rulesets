rule TTP_XOR_WriteProcessMemory_a29c {
  strings:
    $key_a29c = { f5 ee [2] c7 cc [2] c1 f9 [2] ef f9 [2] d0 e5 }

  condition:
    any of them
}