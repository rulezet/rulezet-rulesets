rule TTP_XOR_WriteProcessMemory_1a93 {
  strings:
    $key_1a93 = { 4d e1 [2] 7f c3 [2] 79 f6 [2] 57 f6 [2] 68 ea }

  condition:
    any of them
}