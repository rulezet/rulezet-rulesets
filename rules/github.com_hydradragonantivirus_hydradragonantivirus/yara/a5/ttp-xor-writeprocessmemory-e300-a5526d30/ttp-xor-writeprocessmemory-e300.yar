rule TTP_XOR_WriteProcessMemory_e300 {
  strings:
    $key_e300 = { b4 72 [2] 86 50 [2] 80 65 [2] ae 65 [2] 91 79 }

  condition:
    any of them
}