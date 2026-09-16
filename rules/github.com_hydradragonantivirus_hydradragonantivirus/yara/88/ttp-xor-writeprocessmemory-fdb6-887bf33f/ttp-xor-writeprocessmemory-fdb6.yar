rule TTP_XOR_WriteProcessMemory_fdb6 {
  strings:
    $key_fdb6 = { aa c4 [2] 98 e6 [2] 9e d3 [2] b0 d3 [2] 8f cf }

  condition:
    any of them
}