rule TTP_XOR_WriteProcessMemory_fc8c {
  strings:
    $key_fc8c = { ab fe [2] 99 dc [2] 9f e9 [2] b1 e9 [2] 8e f5 }

  condition:
    any of them
}