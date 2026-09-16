rule TTP_XOR_WriteProcessMemory_0e83 {
  strings:
    $key_0e83 = { 59 f1 [2] 6b d3 [2] 6d e6 [2] 43 e6 [2] 7c fa }

  condition:
    any of them
}