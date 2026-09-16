rule TTP_XOR_WriteProcessMemory_eb66 {
  strings:
    $key_eb66 = { bc 14 [2] 8e 36 [2] 88 03 [2] a6 03 [2] 99 1f }

  condition:
    any of them
}