rule TTP_XOR_WriteProcessMemory_dc87 {
  strings:
    $key_dc87 = { 8b f5 [2] b9 d7 [2] bf e2 [2] 91 e2 [2] ae fe }

  condition:
    any of them
}