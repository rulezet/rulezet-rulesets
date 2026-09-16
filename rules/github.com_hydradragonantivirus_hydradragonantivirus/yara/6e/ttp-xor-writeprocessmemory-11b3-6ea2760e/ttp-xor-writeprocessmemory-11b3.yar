rule TTP_XOR_WriteProcessMemory_11b3 {
  strings:
    $key_11b3 = { 46 c1 [2] 74 e3 [2] 72 d6 [2] 5c d6 [2] 63 ca }

  condition:
    any of them
}