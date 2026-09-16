rule TTP_XOR_WriteProcessMemory_7183 {
  strings:
    $key_7183 = { 26 f1 [2] 14 d3 [2] 12 e6 [2] 3c e6 [2] 03 fa }

  condition:
    any of them
}