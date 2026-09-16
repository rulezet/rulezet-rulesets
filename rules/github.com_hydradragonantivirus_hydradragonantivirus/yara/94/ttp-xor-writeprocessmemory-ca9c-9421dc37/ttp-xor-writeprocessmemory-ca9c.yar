rule TTP_XOR_WriteProcessMemory_ca9c {
  strings:
    $key_ca9c = { 9d ee [2] af cc [2] a9 f9 [2] 87 f9 [2] b8 e5 }

  condition:
    any of them
}