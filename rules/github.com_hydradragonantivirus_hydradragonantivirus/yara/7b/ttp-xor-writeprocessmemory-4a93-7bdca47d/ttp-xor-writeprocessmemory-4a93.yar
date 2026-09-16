rule TTP_XOR_WriteProcessMemory_4a93 {
  strings:
    $key_4a93 = { 1d e1 [2] 2f c3 [2] 29 f6 [2] 07 f6 [2] 38 ea }

  condition:
    any of them
}