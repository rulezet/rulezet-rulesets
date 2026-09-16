rule TTP_XOR_WriteProcessMemory_e3c7 {
  strings:
    $key_e3c7 = { b4 b5 [2] 86 97 [2] 80 a2 [2] ae a2 [2] 91 be }

  condition:
    any of them
}