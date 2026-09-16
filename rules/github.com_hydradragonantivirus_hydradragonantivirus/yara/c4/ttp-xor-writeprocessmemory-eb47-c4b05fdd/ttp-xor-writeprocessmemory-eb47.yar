rule TTP_XOR_WriteProcessMemory_eb47 {
  strings:
    $key_eb47 = { bc 35 [2] 8e 17 [2] 88 22 [2] a6 22 [2] 99 3e }

  condition:
    any of them
}