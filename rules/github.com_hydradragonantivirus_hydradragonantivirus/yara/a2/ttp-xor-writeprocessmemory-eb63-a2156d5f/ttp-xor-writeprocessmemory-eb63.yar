rule TTP_XOR_WriteProcessMemory_eb63 {
  strings:
    $key_eb63 = { bc 11 [2] 8e 33 [2] 88 06 [2] a6 06 [2] 99 1a }

  condition:
    any of them
}