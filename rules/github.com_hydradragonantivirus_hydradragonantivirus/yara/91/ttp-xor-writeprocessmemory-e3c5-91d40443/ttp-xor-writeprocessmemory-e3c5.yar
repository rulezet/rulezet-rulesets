rule TTP_XOR_WriteProcessMemory_e3c5 {
  strings:
    $key_e3c5 = { b4 b7 [2] 86 95 [2] 80 a0 [2] ae a0 [2] 91 bc }

  condition:
    any of them
}