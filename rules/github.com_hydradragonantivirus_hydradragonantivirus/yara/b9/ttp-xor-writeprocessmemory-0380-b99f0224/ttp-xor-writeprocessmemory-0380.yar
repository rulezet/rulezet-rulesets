rule TTP_XOR_WriteProcessMemory_0380 {
  strings:
    $key_0380 = { 54 f2 [2] 66 d0 [2] 60 e5 [2] 4e e5 [2] 71 f9 }

  condition:
    any of them
}