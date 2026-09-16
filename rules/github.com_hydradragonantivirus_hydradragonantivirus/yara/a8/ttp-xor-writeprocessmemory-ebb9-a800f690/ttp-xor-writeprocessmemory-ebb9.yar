rule TTP_XOR_WriteProcessMemory_ebb9 {
  strings:
    $key_ebb9 = { bc cb [2] 8e e9 [2] 88 dc [2] a6 dc [2] 99 c0 }

  condition:
    any of them
}