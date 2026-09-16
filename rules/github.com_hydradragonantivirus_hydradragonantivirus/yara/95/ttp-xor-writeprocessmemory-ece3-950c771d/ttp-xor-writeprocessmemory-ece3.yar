rule TTP_XOR_WriteProcessMemory_ece3 {
  strings:
    $key_ece3 = { bb 91 [2] 89 b3 [2] 8f 86 [2] a1 86 [2] 9e 9a }

  condition:
    any of them
}