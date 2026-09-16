rule TTP_XOR_WriteProcessMemory_e293 {
  strings:
    $key_e293 = { b5 e1 [2] 87 c3 [2] 81 f6 [2] af f6 [2] 90 ea }

  condition:
    any of them
}