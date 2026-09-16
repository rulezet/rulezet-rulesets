rule TTP_XOR_WriteProcessMemory_ec6c {
  strings:
    $key_ec6c = { bb 1e [2] 89 3c [2] 8f 09 [2] a1 09 [2] 9e 15 }

  condition:
    any of them
}