rule TTP_XOR_WriteProcessMemory_f8dd {
  strings:
    $key_f8dd = { af af [2] 9d 8d [2] 9b b8 [2] b5 b8 [2] 8a a4 }

  condition:
    any of them
}