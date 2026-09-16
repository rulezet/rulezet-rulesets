rule TTP_XOR_WriteProcessMemory_7cb3 {
  strings:
    $key_7cb3 = { 2b c1 [2] 19 e3 [2] 1f d6 [2] 31 d6 [2] 0e ca }

  condition:
    any of them
}