rule TTP_XOR_WriteProcessMemory_ec0f {
  strings:
    $key_ec0f = { bb 7d [2] 89 5f [2] 8f 6a [2] a1 6a [2] 9e 76 }

  condition:
    any of them
}