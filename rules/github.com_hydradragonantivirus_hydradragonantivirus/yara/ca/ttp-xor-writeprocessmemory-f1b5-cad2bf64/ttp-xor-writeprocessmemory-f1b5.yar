rule TTP_XOR_WriteProcessMemory_f1b5 {
  strings:
    $key_f1b5 = { a6 c7 [2] 94 e5 [2] 92 d0 [2] bc d0 [2] 83 cc }

  condition:
    any of them
}