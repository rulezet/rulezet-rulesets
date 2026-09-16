rule TTP_XOR_WriteProcessMemory_f580 {
  strings:
    $key_f580 = { a2 f2 [2] 90 d0 [2] 96 e5 [2] b8 e5 [2] 87 f9 }

  condition:
    any of them
}