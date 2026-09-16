rule TTP_XOR_WriteProcessMemory_ec1d {
  strings:
    $key_ec1d = { bb 6f [2] 89 4d [2] 8f 78 [2] a1 78 [2] 9e 64 }

  condition:
    any of them
}