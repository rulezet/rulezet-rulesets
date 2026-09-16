rule TTP_XOR_WriteProcessMemory_0c80 {
  strings:
    $key_0c80 = { 5b f2 [2] 69 d0 [2] 6f e5 [2] 41 e5 [2] 7e f9 }

  condition:
    any of them
}