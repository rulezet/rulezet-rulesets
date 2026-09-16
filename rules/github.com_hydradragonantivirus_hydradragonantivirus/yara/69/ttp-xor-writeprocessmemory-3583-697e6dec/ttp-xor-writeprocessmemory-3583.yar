rule TTP_XOR_WriteProcessMemory_3583 {
  strings:
    $key_3583 = { 62 f1 [2] 50 d3 [2] 56 e6 [2] 78 e6 [2] 47 fa }

  condition:
    any of them
}