rule TTP_XOR_WriteProcessMemory_d607 {
  strings:
    $key_d607 = { 81 75 [2] b3 57 [2] b5 62 [2] 9b 62 [2] a4 7e }

  condition:
    any of them
}