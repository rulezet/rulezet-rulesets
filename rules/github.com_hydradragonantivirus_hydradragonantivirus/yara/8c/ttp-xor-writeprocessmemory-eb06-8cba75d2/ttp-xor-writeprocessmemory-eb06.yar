rule TTP_XOR_WriteProcessMemory_eb06 {
  strings:
    $key_eb06 = { bc 74 [2] 8e 56 [2] 88 63 [2] a6 63 [2] 99 7f }

  condition:
    any of them
}