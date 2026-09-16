rule TTP_XOR_WriteProcessMemory_e183 {
  strings:
    $key_e183 = { b6 f1 [2] 84 d3 [2] 82 e6 [2] ac e6 [2] 93 fa }

  condition:
    any of them
}