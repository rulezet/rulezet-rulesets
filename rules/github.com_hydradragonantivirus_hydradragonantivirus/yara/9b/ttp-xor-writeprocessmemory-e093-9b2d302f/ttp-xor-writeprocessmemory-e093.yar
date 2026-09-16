rule TTP_XOR_WriteProcessMemory_e093 {
  strings:
    $key_e093 = { b7 e1 [2] 85 c3 [2] 83 f6 [2] ad f6 [2] 92 ea }

  condition:
    any of them
}