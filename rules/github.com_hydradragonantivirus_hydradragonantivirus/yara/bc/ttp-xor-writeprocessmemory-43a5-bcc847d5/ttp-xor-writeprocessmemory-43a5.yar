rule TTP_XOR_WriteProcessMemory_43a5 {
  strings:
    $key_43a5 = { 14 d7 [2] 26 f5 [2] 20 c0 [2] 0e c0 [2] 31 dc }

  condition:
    any of them
}