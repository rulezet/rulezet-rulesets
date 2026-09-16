rule TTP_XOR_WriteProcessMemory_43c4 {
  strings:
    $key_43c4 = { 14 b6 [2] 26 94 [2] 20 a1 [2] 0e a1 [2] 31 bd }

  condition:
    any of them
}