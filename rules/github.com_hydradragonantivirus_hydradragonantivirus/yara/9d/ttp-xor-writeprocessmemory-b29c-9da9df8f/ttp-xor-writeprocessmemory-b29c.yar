rule TTP_XOR_WriteProcessMemory_b29c {
  strings:
    $key_b29c = { e5 ee [2] d7 cc [2] d1 f9 [2] ff f9 [2] c0 e5 }

  condition:
    any of them
}