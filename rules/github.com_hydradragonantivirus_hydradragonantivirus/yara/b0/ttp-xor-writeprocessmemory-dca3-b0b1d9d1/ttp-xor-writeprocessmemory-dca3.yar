rule TTP_XOR_WriteProcessMemory_dca3 {
  strings:
    $key_dca3 = { 8b d1 [2] b9 f3 [2] bf c6 [2] 91 c6 [2] ae da }

  condition:
    any of them
}