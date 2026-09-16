rule TTP_XOR_WriteProcessMemory_3fb3 {
  strings:
    $key_3fb3 = { 68 c1 [2] 5a e3 [2] 5c d6 [2] 72 d6 [2] 4d ca }

  condition:
    any of them
}