rule TTP_XOR_WriteProcessMemory_6c80 {
  strings:
    $key_6c80 = { 3b f2 [2] 09 d0 [2] 0f e5 [2] 21 e5 [2] 1e f9 }

  condition:
    any of them
}