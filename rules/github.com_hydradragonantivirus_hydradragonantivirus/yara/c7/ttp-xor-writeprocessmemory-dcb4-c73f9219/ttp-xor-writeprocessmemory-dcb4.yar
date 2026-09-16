rule TTP_XOR_WriteProcessMemory_dcb4 {
  strings:
    $key_dcb4 = { 8b c6 [2] b9 e4 [2] bf d1 [2] 91 d1 [2] ae cd }

  condition:
    any of them
}