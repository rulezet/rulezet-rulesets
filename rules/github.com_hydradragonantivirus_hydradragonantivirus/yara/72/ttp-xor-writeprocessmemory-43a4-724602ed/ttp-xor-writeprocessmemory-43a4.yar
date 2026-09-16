rule TTP_XOR_WriteProcessMemory_43a4 {
  strings:
    $key_43a4 = { 14 d6 [2] 26 f4 [2] 20 c1 [2] 0e c1 [2] 31 dd }

  condition:
    any of them
}