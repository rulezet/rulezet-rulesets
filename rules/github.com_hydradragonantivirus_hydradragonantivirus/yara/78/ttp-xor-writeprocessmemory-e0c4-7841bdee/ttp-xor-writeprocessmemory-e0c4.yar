rule TTP_XOR_WriteProcessMemory_e0c4 {
  strings:
    $key_e0c4 = { b7 b6 [2] 85 94 [2] 83 a1 [2] ad a1 [2] 92 bd }

  condition:
    any of them
}