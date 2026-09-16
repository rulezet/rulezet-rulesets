rule TTP_XOR_WriteProcessMemory_f7e3 {
  strings:
    $key_f7e3 = { a0 91 [2] 92 b3 [2] 94 86 [2] ba 86 [2] 85 9a }

  condition:
    any of them
}