rule TTP_XOR_WriteProcessMemory_43a6 {
  strings:
    $key_43a6 = { 14 d4 [2] 26 f6 [2] 20 c3 [2] 0e c3 [2] 31 df }

  condition:
    any of them
}