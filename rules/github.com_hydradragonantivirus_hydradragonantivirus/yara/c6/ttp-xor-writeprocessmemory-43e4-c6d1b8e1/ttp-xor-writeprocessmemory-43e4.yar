rule TTP_XOR_WriteProcessMemory_43e4 {
  strings:
    $key_43e4 = { 14 96 [2] 26 b4 [2] 20 81 [2] 0e 81 [2] 31 9d }

  condition:
    any of them
}