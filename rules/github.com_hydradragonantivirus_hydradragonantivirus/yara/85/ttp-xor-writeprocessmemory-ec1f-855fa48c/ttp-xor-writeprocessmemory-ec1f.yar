rule TTP_XOR_WriteProcessMemory_ec1f {
  strings:
    $key_ec1f = { bb 6d [2] 89 4f [2] 8f 7a [2] a1 7a [2] 9e 66 }

  condition:
    any of them
}