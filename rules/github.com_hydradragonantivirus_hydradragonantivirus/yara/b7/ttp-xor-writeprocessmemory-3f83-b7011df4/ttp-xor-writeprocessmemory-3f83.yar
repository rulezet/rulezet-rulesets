rule TTP_XOR_WriteProcessMemory_3f83 {
  strings:
    $key_3f83 = { 68 f1 [2] 5a d3 [2] 5c e6 [2] 72 e6 [2] 4d fa }

  condition:
    any of them
}