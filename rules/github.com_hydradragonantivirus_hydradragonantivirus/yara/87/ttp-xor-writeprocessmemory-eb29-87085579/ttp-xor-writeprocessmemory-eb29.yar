rule TTP_XOR_WriteProcessMemory_eb29 {
  strings:
    $key_eb29 = { bc 5b [2] 8e 79 [2] 88 4c [2] a6 4c [2] 99 50 }

  condition:
    any of them
}