rule TTP_XOR_WriteProcessMemory_eb70 {
  strings:
    $key_eb70 = { bc 02 [2] 8e 20 [2] 88 15 [2] a6 15 [2] 99 09 }

  condition:
    any of them
}