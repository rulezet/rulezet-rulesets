rule TTP_XOR_WriteProcessMemory_67b3 {
  strings:
    $key_67b3 = { 30 c1 [2] 02 e3 [2] 04 d6 [2] 2a d6 [2] 15 ca }

  condition:
    any of them
}