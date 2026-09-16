rule TTP_XOR_WriteProcessMemory_eb40 {
  strings:
    $key_eb40 = { bc 32 [2] 8e 10 [2] 88 25 [2] a6 25 [2] 99 39 }

  condition:
    any of them
}