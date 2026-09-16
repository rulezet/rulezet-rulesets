rule TTP_XOR_WriteProcessMemory_ec7e {
  strings:
    $key_ec7e = { bb 0c [2] 89 2e [2] 8f 1b [2] a1 1b [2] 9e 07 }

  condition:
    any of them
}