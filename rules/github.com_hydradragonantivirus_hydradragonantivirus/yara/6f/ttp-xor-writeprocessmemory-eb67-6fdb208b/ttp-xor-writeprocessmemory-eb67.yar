rule TTP_XOR_WriteProcessMemory_eb67 {
  strings:
    $key_eb67 = { bc 15 [2] 8e 37 [2] 88 02 [2] a6 02 [2] 99 1e }

  condition:
    any of them
}