rule TTP_XOR_WriteProcessMemory_32a6 {
  strings:
    $key_32a6 = { 65 d4 [2] 57 f6 [2] 51 c3 [2] 7f c3 [2] 40 df }

  condition:
    any of them
}