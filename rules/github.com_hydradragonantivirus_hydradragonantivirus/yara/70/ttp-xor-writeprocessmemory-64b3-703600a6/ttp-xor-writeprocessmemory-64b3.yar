rule TTP_XOR_WriteProcessMemory_64b3 {
  strings:
    $key_64b3 = { 33 c1 [2] 01 e3 [2] 07 d6 [2] 29 d6 [2] 16 ca }

  condition:
    any of them
}