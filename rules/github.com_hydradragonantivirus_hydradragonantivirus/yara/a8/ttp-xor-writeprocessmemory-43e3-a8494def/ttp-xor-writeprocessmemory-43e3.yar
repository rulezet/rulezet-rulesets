rule TTP_XOR_WriteProcessMemory_43e3 {
  strings:
    $key_43e3 = { 14 91 [2] 26 b3 [2] 20 86 [2] 0e 86 [2] 31 9a }

  condition:
    any of them
}