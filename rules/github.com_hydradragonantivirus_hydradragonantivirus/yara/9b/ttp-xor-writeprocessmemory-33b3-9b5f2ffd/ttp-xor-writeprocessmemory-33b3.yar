rule TTP_XOR_WriteProcessMemory_33b3 {
  strings:
    $key_33b3 = { 64 c1 [2] 56 e3 [2] 50 d6 [2] 7e d6 [2] 41 ca }

  condition:
    any of them
}