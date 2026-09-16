rule TTP_XOR_WriteProcessMemory_eb1e {
  strings:
    $key_eb1e = { bc 6c [2] 8e 4e [2] 88 7b [2] a6 7b [2] 99 67 }

  condition:
    any of them
}