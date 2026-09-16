rule TTP_XOR_WriteProcessMemory_f5dd {
  strings:
    $key_f5dd = { a2 af [2] 90 8d [2] 96 b8 [2] b8 b8 [2] 87 a4 }

  condition:
    any of them
}