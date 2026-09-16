rule TTP_XOR_WriteProcessMemory_19c6 {
  strings:
    $key_19c6 = { 4e b4 [2] 7c 96 [2] 7a a3 [2] 54 a3 [2] 6b bf }

  condition:
    any of them
}