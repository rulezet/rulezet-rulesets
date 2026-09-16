rule TTP_XOR_WriteProcessMemory_ef80 {
  strings:
    $key_ef80 = { b8 f2 [2] 8a d0 [2] 8c e5 [2] a2 e5 [2] 9d f9 }

  condition:
    any of them
}