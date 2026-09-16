rule TTP_XOR_WriteProcessMemory_ec4c {
  strings:
    $key_ec4c = { bb 3e [2] 89 1c [2] 8f 29 [2] a1 29 [2] 9e 35 }

  condition:
    any of them
}