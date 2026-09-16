rule TTP_XOR_WriteProcessMemory_2fb3 {
  strings:
    $key_2fb3 = { 78 c1 [2] 4a e3 [2] 4c d6 [2] 62 d6 [2] 5d ca }

  condition:
    any of them
}