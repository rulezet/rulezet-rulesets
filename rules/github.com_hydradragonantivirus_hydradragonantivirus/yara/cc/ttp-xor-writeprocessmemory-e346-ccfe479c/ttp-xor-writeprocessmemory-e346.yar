rule TTP_XOR_WriteProcessMemory_e346 {
  strings:
    $key_e346 = { b4 34 [2] 86 16 [2] 80 23 [2] ae 23 [2] 91 3f }

  condition:
    any of them
}