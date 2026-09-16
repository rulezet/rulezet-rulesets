rule TTP_XOR_WriteProcessMemory_e3c6 {
  strings:
    $key_e3c6 = { b4 b4 [2] 86 96 [2] 80 a3 [2] ae a3 [2] 91 bf }

  condition:
    any of them
}