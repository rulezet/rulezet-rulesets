rule TTP_XOR_WriteProcessMemory_30b3 {
  strings:
    $key_30b3 = { 67 c1 [2] 55 e3 [2] 53 d6 [2] 7d d6 [2] 42 ca }

  condition:
    any of them
}