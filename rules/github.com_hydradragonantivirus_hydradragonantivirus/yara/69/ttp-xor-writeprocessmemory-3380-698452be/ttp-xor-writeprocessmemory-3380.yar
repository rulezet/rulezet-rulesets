rule TTP_XOR_WriteProcessMemory_3380 {
  strings:
    $key_3380 = { 64 f2 [2] 56 d0 [2] 50 e5 [2] 7e e5 [2] 41 f9 }

  condition:
    any of them
}