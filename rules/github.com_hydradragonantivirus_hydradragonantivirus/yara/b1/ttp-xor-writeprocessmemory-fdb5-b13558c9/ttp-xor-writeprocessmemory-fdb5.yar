rule TTP_XOR_WriteProcessMemory_fdb5 {
  strings:
    $key_fdb5 = { aa c7 [2] 98 e5 [2] 9e d0 [2] b0 d0 [2] 8f cc }

  condition:
    any of them
}