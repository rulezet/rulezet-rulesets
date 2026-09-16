rule TTP_XOR_WriteProcessMemory_fc83 {
  strings:
    $key_fc83 = { ab f1 [2] 99 d3 [2] 9f e6 [2] b1 e6 [2] 8e fa }

  condition:
    any of them
}