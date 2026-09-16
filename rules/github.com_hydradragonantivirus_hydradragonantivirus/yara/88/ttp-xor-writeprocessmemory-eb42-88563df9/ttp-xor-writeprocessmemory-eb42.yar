rule TTP_XOR_WriteProcessMemory_eb42 {
  strings:
    $key_eb42 = { bc 30 [2] 8e 12 [2] 88 27 [2] a6 27 [2] 99 3b }

  condition:
    any of them
}