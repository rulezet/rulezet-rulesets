rule TTP_XOR_WriteProcessMemory_dcb2 {
  strings:
    $key_dcb2 = { 8b c0 [2] b9 e2 [2] bf d7 [2] 91 d7 [2] ae cb }

  condition:
    any of them
}