rule TTP_XOR_WriteProcessMemory_eb07 {
  strings:
    $key_eb07 = { bc 75 [2] 8e 57 [2] 88 62 [2] a6 62 [2] 99 7e }

  condition:
    any of them
}