rule TTP_XOR_WriteProcessMemory_32b3 {
  strings:
    $key_32b3 = { 65 c1 [2] 57 e3 [2] 51 d6 [2] 7f d6 [2] 40 ca }

  condition:
    any of them
}