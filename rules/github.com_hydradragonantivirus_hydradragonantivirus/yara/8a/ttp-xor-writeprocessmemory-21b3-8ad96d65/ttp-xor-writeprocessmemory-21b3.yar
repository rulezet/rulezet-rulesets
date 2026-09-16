rule TTP_XOR_WriteProcessMemory_21b3 {
  strings:
    $key_21b3 = { 76 c1 [2] 44 e3 [2] 42 d6 [2] 6c d6 [2] 53 ca }

  condition:
    any of them
}