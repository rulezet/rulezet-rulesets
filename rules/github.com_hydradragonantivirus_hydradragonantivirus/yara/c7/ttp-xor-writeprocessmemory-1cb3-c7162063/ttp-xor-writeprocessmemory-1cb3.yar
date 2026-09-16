rule TTP_XOR_WriteProcessMemory_1cb3 {
  strings:
    $key_1cb3 = { 4b c1 [2] 79 e3 [2] 7f d6 [2] 51 d6 [2] 6e ca }

  condition:
    any of them
}