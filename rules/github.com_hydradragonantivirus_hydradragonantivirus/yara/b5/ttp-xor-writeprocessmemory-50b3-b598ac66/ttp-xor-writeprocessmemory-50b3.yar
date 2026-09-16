rule TTP_XOR_WriteProcessMemory_50b3 {
  strings:
    $key_50b3 = { 07 c1 [2] 35 e3 [2] 33 d6 [2] 1d d6 [2] 22 ca }

  condition:
    any of them
}