rule TTP_XOR_WriteProcessMemory_17b3 {
  strings:
    $key_17b3 = { 40 c1 [2] 72 e3 [2] 74 d6 [2] 5a d6 [2] 65 ca }

  condition:
    any of them
}