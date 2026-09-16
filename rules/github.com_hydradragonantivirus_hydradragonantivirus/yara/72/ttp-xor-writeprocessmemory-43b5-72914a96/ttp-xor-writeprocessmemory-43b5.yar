rule TTP_XOR_WriteProcessMemory_43b5 {
  strings:
    $key_43b5 = { 14 c7 [2] 26 e5 [2] 20 d0 [2] 0e d0 [2] 31 cc }

  condition:
    any of them
}