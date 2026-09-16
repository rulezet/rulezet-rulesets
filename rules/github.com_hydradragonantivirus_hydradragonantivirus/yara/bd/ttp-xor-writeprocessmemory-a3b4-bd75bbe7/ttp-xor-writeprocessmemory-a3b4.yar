rule TTP_XOR_WriteProcessMemory_a3b4 {
  strings:
    $key_a3b4 = { f4 c6 [2] c6 e4 [2] c0 d1 [2] ee d1 [2] d1 cd }

  condition:
    any of them
}