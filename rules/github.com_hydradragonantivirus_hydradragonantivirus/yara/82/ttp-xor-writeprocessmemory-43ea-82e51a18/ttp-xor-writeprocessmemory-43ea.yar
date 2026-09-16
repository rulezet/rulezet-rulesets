rule TTP_XOR_WriteProcessMemory_43ea {
  strings:
    $key_43ea = { 14 98 [2] 26 ba [2] 20 8f [2] 0e 8f [2] 31 93 }

  condition:
    any of them
}