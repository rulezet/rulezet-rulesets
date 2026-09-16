rule TTP_XOR_WriteProcessMemory_eb03 {
  strings:
    $key_eb03 = { bc 71 [2] 8e 53 [2] 88 66 [2] a6 66 [2] 99 7a }

  condition:
    any of them
}