rule TTP_XOR_WriteProcessMemory_0183 {
  strings:
    $key_0183 = { 56 f1 [2] 64 d3 [2] 62 e6 [2] 4c e6 [2] 73 fa }

  condition:
    any of them
}