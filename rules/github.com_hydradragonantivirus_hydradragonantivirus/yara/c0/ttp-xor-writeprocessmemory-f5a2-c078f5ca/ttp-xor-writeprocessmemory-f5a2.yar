rule TTP_XOR_WriteProcessMemory_f5a2 {
  strings:
    $key_f5a2 = { a2 d0 [2] 90 f2 [2] 96 c7 [2] b8 c7 [2] 87 db }

  condition:
    any of them
}