rule TTP_XOR_WriteProcessMemory_eb6c {
  strings:
    $key_eb6c = { bc 1e [2] 8e 3c [2] 88 09 [2] a6 09 [2] 99 15 }

  condition:
    any of them
}