rule TTP_XOR_WriteProcessMemory_2a93 {
  strings:
    $key_2a93 = { 7d e1 [2] 4f c3 [2] 49 f6 [2] 67 f6 [2] 58 ea }

  condition:
    any of them
}