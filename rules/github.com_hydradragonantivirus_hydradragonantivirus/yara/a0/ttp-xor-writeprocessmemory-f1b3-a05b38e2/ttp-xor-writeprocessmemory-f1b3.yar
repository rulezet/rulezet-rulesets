rule TTP_XOR_WriteProcessMemory_f1b3 {
  strings:
    $key_f1b3 = { a6 c1 [2] 94 e3 [2] 92 d6 [2] bc d6 [2] 83 ca }

  condition:
    any of them
}