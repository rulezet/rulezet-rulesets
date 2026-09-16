rule TTP_XOR_WriteProcessMemory_eb53 {
  strings:
    $key_eb53 = { bc 21 [2] 8e 03 [2] 88 36 [2] a6 36 [2] 99 2a }

  condition:
    any of them
}