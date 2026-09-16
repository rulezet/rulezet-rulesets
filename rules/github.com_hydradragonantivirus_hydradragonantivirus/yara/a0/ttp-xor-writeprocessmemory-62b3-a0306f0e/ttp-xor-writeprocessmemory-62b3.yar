rule TTP_XOR_WriteProcessMemory_62b3 {
  strings:
    $key_62b3 = { 35 c1 [2] 07 e3 [2] 01 d6 [2] 2f d6 [2] 10 ca }

  condition:
    any of them
}