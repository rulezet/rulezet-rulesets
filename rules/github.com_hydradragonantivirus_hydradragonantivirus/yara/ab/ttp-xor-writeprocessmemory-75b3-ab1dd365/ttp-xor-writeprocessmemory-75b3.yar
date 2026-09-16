rule TTP_XOR_WriteProcessMemory_75b3 {
  strings:
    $key_75b3 = { 22 c1 [2] 10 e3 [2] 16 d6 [2] 38 d6 [2] 07 ca }

  condition:
    any of them
}