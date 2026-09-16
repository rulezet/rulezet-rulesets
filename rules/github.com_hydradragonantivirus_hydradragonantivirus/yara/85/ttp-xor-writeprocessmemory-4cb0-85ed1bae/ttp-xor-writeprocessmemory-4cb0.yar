rule TTP_XOR_WriteProcessMemory_4cb0 {
  strings:
    $key_4cb0 = { 1b c2 [2] 29 e0 [2] 2f d5 [2] 01 d5 [2] 3e c9 }

  condition:
    any of them
}