rule TTP_XOR_WriteProcessMemory_ec6e {
  strings:
    $key_ec6e = { bb 1c [2] 89 3e [2] 8f 0b [2] a1 0b [2] 9e 17 }

  condition:
    any of them
}