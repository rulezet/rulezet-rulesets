rule TTP_XOR_WriteProcessMemory_eb21 {
  strings:
    $key_eb21 = { bc 53 [2] 8e 71 [2] 88 44 [2] a6 44 [2] 99 58 }

  condition:
    any of them
}