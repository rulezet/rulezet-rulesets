rule TTP_XOR_WriteProcessMemory_ec0e {
  strings:
    $key_ec0e = { bb 7c [2] 89 5e [2] 8f 6b [2] a1 6b [2] 9e 77 }

  condition:
    any of them
}