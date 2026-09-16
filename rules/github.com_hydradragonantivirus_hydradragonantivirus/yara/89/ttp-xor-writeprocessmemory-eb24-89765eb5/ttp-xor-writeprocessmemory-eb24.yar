rule TTP_XOR_WriteProcessMemory_eb24 {
  strings:
    $key_eb24 = { bc 56 [2] 8e 74 [2] 88 41 [2] a6 41 [2] 99 5d }

  condition:
    any of them
}