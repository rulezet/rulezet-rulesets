rule TTP_XOR_WriteProcessMemory_5c80 {
  strings:
    $key_5c80 = { 0b f2 [2] 39 d0 [2] 3f e5 [2] 11 e5 [2] 2e f9 }

  condition:
    any of them
}