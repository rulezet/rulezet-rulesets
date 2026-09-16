rule TTP_XOR_WriteProcessMemory_ec3e {
  strings:
    $key_ec3e = { bb 4c [2] 89 6e [2] 8f 5b [2] a1 5b [2] 9e 47 }

  condition:
    any of them
}