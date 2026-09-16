rule TTP_XOR_WriteProcessMemory_eb20 {
  strings:
    $key_eb20 = { bc 52 [2] 8e 70 [2] 88 45 [2] a6 45 [2] 99 59 }

  condition:
    any of them
}