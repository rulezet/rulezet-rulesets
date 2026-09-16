rule TTP_XOR_WriteProcessMemory_e980 {
  strings:
    $key_e980 = { be f2 [2] 8c d0 [2] 8a e5 [2] a4 e5 [2] 9b f9 }

  condition:
    any of them
}