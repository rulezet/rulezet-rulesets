rule TTP_XOR_WriteProcessMemory_eb25 {
  strings:
    $key_eb25 = { bc 57 [2] 8e 75 [2] 88 40 [2] a6 40 [2] 99 5c }

  condition:
    any of them
}