rule TTP_XOR_WriteProcessMemory_5283 {
  strings:
    $key_5283 = { 05 f1 [2] 37 d3 [2] 31 e6 [2] 1f e6 [2] 20 fa }

  condition:
    any of them
}