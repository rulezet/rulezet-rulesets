rule TTP_XOR_WriteProcessMemory_3cb3 {
  strings:
    $key_3cb3 = { 6b c1 [2] 59 e3 [2] 5f d6 [2] 71 d6 [2] 4e ca }

  condition:
    any of them
}