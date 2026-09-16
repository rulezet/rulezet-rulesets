rule TTP_XOR_WriteProcessMemory_43b3 {
  strings:
    $key_43b3 = { 14 c1 [2] 26 e3 [2] 20 d6 [2] 0e d6 [2] 31 ca }

  condition:
    any of them
}