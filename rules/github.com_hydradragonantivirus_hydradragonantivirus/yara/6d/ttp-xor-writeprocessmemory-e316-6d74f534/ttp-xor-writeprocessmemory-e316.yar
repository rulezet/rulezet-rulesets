rule TTP_XOR_WriteProcessMemory_e316 {
  strings:
    $key_e316 = { b4 64 [2] 86 46 [2] 80 73 [2] ae 73 [2] 91 6f }

  condition:
    any of them
}