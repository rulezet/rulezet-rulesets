rule TTP_XOR_WriteProcessMemory_eb7e {
  strings:
    $key_eb7e = { bc 0c [2] 8e 2e [2] 88 1b [2] a6 1b [2] 99 07 }

  condition:
    any of them
}