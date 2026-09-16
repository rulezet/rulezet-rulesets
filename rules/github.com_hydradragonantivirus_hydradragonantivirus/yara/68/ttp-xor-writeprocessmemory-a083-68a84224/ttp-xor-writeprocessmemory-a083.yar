rule TTP_XOR_WriteProcessMemory_a083 {
  strings:
    $key_a083 = { f7 f1 [2] c5 d3 [2] c3 e6 [2] ed e6 [2] d2 fa }

  condition:
    any of them
}