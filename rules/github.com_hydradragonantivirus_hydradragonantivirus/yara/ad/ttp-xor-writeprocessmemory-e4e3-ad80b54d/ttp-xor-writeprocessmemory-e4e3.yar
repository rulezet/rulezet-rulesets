rule TTP_XOR_WriteProcessMemory_e4e3 {
  strings:
    $key_e4e3 = { b3 91 [2] 81 b3 [2] 87 86 [2] a9 86 [2] 96 9a }

  condition:
    any of them
}