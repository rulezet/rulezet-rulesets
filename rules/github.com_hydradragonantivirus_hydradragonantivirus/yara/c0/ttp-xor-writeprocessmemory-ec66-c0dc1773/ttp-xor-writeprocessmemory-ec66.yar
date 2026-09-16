rule TTP_XOR_WriteProcessMemory_ec66 {
  strings:
    $key_ec66 = { bb 14 [2] 89 36 [2] 8f 03 [2] a1 03 [2] 9e 1f }

  condition:
    any of them
}