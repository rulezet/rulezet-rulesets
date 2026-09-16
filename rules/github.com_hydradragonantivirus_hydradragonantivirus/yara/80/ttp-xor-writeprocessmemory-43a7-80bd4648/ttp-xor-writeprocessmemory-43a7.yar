rule TTP_XOR_WriteProcessMemory_43a7 {
  strings:
    $key_43a7 = { 14 d5 [2] 26 f7 [2] 20 c2 [2] 0e c2 [2] 31 de }

  condition:
    any of them
}