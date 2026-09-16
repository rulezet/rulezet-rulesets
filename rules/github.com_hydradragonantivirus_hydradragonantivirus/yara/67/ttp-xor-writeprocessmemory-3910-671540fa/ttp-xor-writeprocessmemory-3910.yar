rule TTP_XOR_WriteProcessMemory_3910 {
  strings:
    $key_3910 = { 6e 62 [2] 5c 40 [2] 5a 75 [2] 74 75 [2] 4b 69 }

  condition:
    any of them
}