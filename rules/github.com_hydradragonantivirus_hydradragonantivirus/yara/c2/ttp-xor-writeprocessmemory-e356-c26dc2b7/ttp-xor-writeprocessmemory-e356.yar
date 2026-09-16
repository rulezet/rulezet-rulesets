rule TTP_XOR_WriteProcessMemory_e356 {
  strings:
    $key_e356 = { b4 24 [2] 86 06 [2] 80 33 [2] ae 33 [2] 91 2f }

  condition:
    any of them
}