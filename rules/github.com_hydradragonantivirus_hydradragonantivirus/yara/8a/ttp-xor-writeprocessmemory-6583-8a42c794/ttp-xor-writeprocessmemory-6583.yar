rule TTP_XOR_WriteProcessMemory_6583 {
  strings:
    $key_6583 = { 32 f1 [2] 00 d3 [2] 06 e6 [2] 28 e6 [2] 17 fa }

  condition:
    any of them
}