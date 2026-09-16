rule TTP_XOR_WriteProcessMemory_f59c {
  strings:
    $key_f59c = { a2 ee [2] 90 cc [2] 96 f9 [2] b8 f9 [2] 87 e5 }

  condition:
    any of them
}