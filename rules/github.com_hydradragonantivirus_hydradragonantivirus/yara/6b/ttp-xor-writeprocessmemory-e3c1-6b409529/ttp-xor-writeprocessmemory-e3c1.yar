rule TTP_XOR_WriteProcessMemory_e3c1 {
  strings:
    $key_e3c1 = { b4 b3 [2] 86 91 [2] 80 a4 [2] ae a4 [2] 91 b8 }

  condition:
    any of them
}