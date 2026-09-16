rule TTP_XOR_WriteProcessMemory_eb5c {
  strings:
    $key_eb5c = { bc 2e [2] 8e 0c [2] 88 39 [2] a6 39 [2] 99 25 }

  condition:
    any of them
}