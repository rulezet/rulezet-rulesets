rule TTP_XOR_WriteProcessMemory_ebb4 {
  strings:
    $key_ebb4 = { bc c6 [2] 8e e4 [2] 88 d1 [2] a6 d1 [2] 99 cd }

  condition:
    any of them
}