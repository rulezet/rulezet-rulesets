rule TTP_XOR_WriteProcessMemory_fdb3 {
  strings:
    $key_fdb3 = { aa c1 [2] 98 e3 [2] 9e d6 [2] b0 d6 [2] 8f ca }

  condition:
    any of them
}