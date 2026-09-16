rule TTP_XOR_WriteProcessMemory_71b3 {
  strings:
    $key_71b3 = { 26 c1 [2] 14 e3 [2] 12 d6 [2] 3c d6 [2] 03 ca }

  condition:
    any of them
}