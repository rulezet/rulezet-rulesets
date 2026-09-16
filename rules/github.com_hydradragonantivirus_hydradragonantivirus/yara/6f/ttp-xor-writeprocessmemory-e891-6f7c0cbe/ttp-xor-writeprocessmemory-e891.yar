rule TTP_XOR_WriteProcessMemory_e891 {
  strings:
    $key_e891 = { bf e3 [2] 8d c1 [2] 8b f4 [2] a5 f4 [2] 9a e8 }

  condition:
    any of them
}