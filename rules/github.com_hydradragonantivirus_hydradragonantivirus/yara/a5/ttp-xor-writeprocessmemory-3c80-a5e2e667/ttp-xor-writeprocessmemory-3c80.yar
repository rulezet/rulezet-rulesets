rule TTP_XOR_WriteProcessMemory_3c80 {
  strings:
    $key_3c80 = { 6b f2 [2] 59 d0 [2] 5f e5 [2] 71 e5 [2] 4e f9 }

  condition:
    any of them
}