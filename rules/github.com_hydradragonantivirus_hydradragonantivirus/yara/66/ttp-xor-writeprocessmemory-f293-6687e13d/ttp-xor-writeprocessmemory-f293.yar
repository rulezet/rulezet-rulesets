rule TTP_XOR_WriteProcessMemory_f293 {
  strings:
    $key_f293 = { a5 e1 [2] 97 c3 [2] 91 f6 [2] bf f6 [2] 80 ea }

  condition:
    any of them
}