rule TTP_XOR_WriteProcessMemory_e883 {
  strings:
    $key_e883 = { bf f1 [2] 8d d3 [2] 8b e6 [2] a5 e6 [2] 9a fa }

  condition:
    any of them
}