rule TTP_XOR_WriteProcessMemory_43a0 {
  strings:
    $key_43a0 = { 14 d2 [2] 26 f0 [2] 20 c5 [2] 0e c5 [2] 31 d9 }

  condition:
    any of them
}