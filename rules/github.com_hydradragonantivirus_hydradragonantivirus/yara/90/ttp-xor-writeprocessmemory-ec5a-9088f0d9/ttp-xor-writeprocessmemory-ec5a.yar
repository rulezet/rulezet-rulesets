rule TTP_XOR_WriteProcessMemory_ec5a {
  strings:
    $key_ec5a = { bb 28 [2] 89 0a [2] 8f 3f [2] a1 3f [2] 9e 23 }

  condition:
    any of them
}