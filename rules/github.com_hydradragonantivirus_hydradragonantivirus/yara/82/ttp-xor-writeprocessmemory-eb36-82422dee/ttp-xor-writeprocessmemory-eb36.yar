rule TTP_XOR_WriteProcessMemory_eb36 {
  strings:
    $key_eb36 = { bc 44 [2] 8e 66 [2] 88 53 [2] a6 53 [2] 99 4f }

  condition:
    any of them
}