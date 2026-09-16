rule TTP_XOR_WriteProcessMemory_e421 {
  strings:
    $key_e421 = { b3 53 [2] 81 71 [2] 87 44 [2] a9 44 [2] 96 58 }

  condition:
    any of them
}