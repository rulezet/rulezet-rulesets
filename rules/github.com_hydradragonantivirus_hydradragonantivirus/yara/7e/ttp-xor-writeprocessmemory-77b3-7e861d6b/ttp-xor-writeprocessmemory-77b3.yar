rule TTP_XOR_WriteProcessMemory_77b3 {
  strings:
    $key_77b3 = { 20 c1 [2] 12 e3 [2] 14 d6 [2] 3a d6 [2] 05 ca }

  condition:
    any of them
}