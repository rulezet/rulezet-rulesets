rule TTP_XOR_WriteProcessMemory_eb37 {
  strings:
    $key_eb37 = { bc 45 [2] 8e 67 [2] 88 52 [2] a6 52 [2] 99 4e }

  condition:
    any of them
}