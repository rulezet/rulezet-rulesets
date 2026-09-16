rule TTP_XOR_WriteProcessMemory_e420 {
  strings:
    $key_e420 = { b3 52 [2] 81 70 [2] 87 45 [2] a9 45 [2] 96 59 }

  condition:
    any of them
}