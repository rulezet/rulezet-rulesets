rule TTP_XOR_WriteProcessMemory_e0b3 {
  strings:
    $key_e0b3 = { b7 c1 [2] 85 e3 [2] 83 d6 [2] ad d6 [2] 92 ca }

  condition:
    any of them
}