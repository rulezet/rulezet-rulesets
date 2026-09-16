rule TTP_XOR_WriteProcessMemory_ec5d {
  strings:
    $key_ec5d = { bb 2f [2] 89 0d [2] 8f 38 [2] a1 38 [2] 9e 24 }

  condition:
    any of them
}