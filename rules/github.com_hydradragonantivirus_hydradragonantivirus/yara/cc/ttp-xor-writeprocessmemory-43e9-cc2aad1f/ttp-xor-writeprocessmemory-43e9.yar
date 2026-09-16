rule TTP_XOR_WriteProcessMemory_43e9 {
  strings:
    $key_43e9 = { 14 9b [2] 26 b9 [2] 20 8c [2] 0e 8c [2] 31 90 }

  condition:
    any of them
}