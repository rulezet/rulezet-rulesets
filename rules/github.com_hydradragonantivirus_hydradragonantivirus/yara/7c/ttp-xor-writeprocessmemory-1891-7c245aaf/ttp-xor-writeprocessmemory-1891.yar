rule TTP_XOR_WriteProcessMemory_1891 {
  strings:
    $key_1891 = { 4f e3 [2] 7d c1 [2] 7b f4 [2] 55 f4 [2] 6a e8 }

  condition:
    any of them
}