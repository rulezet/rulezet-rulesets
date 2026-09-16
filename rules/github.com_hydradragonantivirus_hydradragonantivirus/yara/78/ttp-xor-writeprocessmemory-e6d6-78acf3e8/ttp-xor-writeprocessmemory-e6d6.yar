rule TTP_XOR_WriteProcessMemory_e6d6 {
  strings:
    $key_e6d6 = { b1 a4 [2] 83 86 [2] 85 b3 [2] ab b3 [2] 94 af }

  condition:
    any of them
}