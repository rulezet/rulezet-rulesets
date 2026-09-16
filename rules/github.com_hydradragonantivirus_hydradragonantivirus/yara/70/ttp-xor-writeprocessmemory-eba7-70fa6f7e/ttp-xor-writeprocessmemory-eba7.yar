rule TTP_XOR_WriteProcessMemory_eba7 {
  strings:
    $key_eba7 = { bc d5 [2] 8e f7 [2] 88 c2 [2] a6 c2 [2] 99 de }

  condition:
    any of them
}