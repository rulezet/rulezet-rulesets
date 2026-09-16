rule TTP_XOR_WriteProcessMemory_dca2 {
  strings:
    $key_dca2 = { 8b d0 [2] b9 f2 [2] bf c7 [2] 91 c7 [2] ae db }

  condition:
    any of them
}