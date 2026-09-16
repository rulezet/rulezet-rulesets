rule TTP_XOR_WriteProcessMemory_46b3 {
  strings:
    $key_46b3 = { 11 c1 [2] 23 e3 [2] 25 d6 [2] 0b d6 [2] 34 ca }

  condition:
    any of them
}