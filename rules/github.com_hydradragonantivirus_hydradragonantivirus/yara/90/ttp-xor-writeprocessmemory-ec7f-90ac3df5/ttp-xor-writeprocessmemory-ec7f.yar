rule TTP_XOR_WriteProcessMemory_ec7f {
  strings:
    $key_ec7f = { bb 0d [2] 89 2f [2] 8f 1a [2] a1 1a [2] 9e 06 }

  condition:
    any of them
}