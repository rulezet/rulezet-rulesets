rule TTP_XOR_WriteProcessMemory_e506 {
  strings:
    $key_e506 = { b2 74 [2] 80 56 [2] 86 63 [2] a8 63 [2] 97 7f }

  condition:
    any of them
}