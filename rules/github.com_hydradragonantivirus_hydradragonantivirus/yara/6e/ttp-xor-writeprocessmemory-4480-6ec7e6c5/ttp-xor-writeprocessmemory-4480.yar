rule TTP_XOR_WriteProcessMemory_4480 {
  strings:
    $key_4480 = { 13 f2 [2] 21 d0 [2] 27 e5 [2] 09 e5 [2] 36 f9 }

  condition:
    any of them
}