rule TTP_XOR_WriteProcessMemory_4cb3 {
  strings:
    $key_4cb3 = { 1b c1 [2] 29 e3 [2] 2f d6 [2] 01 d6 [2] 3e ca }

  condition:
    any of them
}