rule TTP_XOR_WriteProcessMemory_e094 {
  strings:
    $key_e094 = { b7 e6 [2] 85 c4 [2] 83 f1 [2] ad f1 [2] 92 ed }

  condition:
    any of them
}