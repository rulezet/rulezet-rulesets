rule TTP_XOR_WriteProcessMemory_efb3 {
  strings:
    $key_efb3 = { b8 c1 [2] 8a e3 [2] 8c d6 [2] a2 d6 [2] 9d ca }

  condition:
    any of them
}