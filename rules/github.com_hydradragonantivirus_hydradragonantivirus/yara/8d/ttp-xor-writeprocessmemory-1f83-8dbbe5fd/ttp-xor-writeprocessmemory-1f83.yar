rule TTP_XOR_WriteProcessMemory_1f83 {
  strings:
    $key_1f83 = { 48 f1 [2] 7a d3 [2] 7c e6 [2] 52 e6 [2] 6d fa }

  condition:
    any of them
}