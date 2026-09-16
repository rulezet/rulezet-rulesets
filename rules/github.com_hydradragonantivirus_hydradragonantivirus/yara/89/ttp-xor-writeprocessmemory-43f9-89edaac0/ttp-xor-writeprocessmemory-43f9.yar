rule TTP_XOR_WriteProcessMemory_43f9 {
  strings:
    $key_43f9 = { 14 8b [2] 26 a9 [2] 20 9c [2] 0e 9c [2] 31 80 }

  condition:
    any of them
}