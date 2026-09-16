rule TTP_XOR_WriteProcessMemory_b28b {
  strings:
    $key_b28b = { e5 f9 [2] d7 db [2] d1 ee [2] ff ee [2] c0 f2 }

  condition:
    any of them
}