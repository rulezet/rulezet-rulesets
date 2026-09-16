rule TTP_XOR_WriteProcessMemory_32a5 {
  strings:
    $key_32a5 = { 65 d7 [2] 57 f5 [2] 51 c0 [2] 7f c0 [2] 40 dc }

  condition:
    any of them
}