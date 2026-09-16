rule TTP_XOR_WriteProcessMemory_eb12 {
  strings:
    $key_eb12 = { bc 60 [2] 8e 42 [2] 88 77 [2] a6 77 [2] 99 6b }

  condition:
    any of them
}