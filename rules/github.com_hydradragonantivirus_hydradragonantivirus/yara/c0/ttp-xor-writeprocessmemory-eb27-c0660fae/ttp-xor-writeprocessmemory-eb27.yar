rule TTP_XOR_WriteProcessMemory_eb27 {
  strings:
    $key_eb27 = { bc 55 [2] 8e 77 [2] 88 42 [2] a6 42 [2] 99 5e }

  condition:
    any of them
}