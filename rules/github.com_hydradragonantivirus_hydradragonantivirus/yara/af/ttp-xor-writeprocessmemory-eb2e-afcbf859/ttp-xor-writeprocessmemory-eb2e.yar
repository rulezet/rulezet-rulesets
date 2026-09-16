rule TTP_XOR_WriteProcessMemory_eb2e {
  strings:
    $key_eb2e = { bc 5c [2] 8e 7e [2] 88 4b [2] a6 4b [2] 99 57 }

  condition:
    any of them
}