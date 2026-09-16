rule TTP_XOR_WriteProcessMemory_32a3 {
  strings:
    $key_32a3 = { 65 d1 [2] 57 f3 [2] 51 c6 [2] 7f c6 [2] 40 da }

  condition:
    any of them
}