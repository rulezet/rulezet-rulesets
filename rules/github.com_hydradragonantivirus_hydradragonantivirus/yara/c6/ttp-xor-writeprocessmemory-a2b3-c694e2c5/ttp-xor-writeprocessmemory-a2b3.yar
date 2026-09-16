rule TTP_XOR_WriteProcessMemory_a2b3 {
  strings:
    $key_a2b3 = { f5 c1 [2] c7 e3 [2] c1 d6 [2] ef d6 [2] d0 ca }

  condition:
    any of them
}