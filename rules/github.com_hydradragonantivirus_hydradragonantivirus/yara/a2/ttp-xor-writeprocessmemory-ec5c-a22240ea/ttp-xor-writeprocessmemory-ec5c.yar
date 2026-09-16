rule TTP_XOR_WriteProcessMemory_ec5c {
  strings:
    $key_ec5c = { bb 2e [2] 89 0c [2] 8f 39 [2] a1 39 [2] 9e 25 }

  condition:
    any of them
}