rule TTP_XOR_WriteProcessMemory_6cb3 {
  strings:
    $key_6cb3 = { 3b c1 [2] 09 e3 [2] 0f d6 [2] 21 d6 [2] 1e ca }

  condition:
    any of them
}