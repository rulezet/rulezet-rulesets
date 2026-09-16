rule TTP_XOR_WriteProcessMemory_43f4 {
  strings:
    $key_43f4 = { 14 86 [2] 26 a4 [2] 20 91 [2] 0e 91 [2] 31 8d }

  condition:
    any of them
}