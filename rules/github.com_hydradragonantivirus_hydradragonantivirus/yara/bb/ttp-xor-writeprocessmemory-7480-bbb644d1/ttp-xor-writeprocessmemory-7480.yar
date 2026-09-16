rule TTP_XOR_WriteProcessMemory_7480 {
  strings:
    $key_7480 = { 23 f2 [2] 11 d0 [2] 17 e5 [2] 39 e5 [2] 06 f9 }

  condition:
    any of them
}