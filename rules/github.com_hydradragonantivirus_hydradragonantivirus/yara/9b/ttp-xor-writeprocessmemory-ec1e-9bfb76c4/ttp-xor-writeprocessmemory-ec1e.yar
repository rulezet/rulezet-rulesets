rule TTP_XOR_WriteProcessMemory_ec1e {
  strings:
    $key_ec1e = { bb 6c [2] 89 4e [2] 8f 7b [2] a1 7b [2] 9e 67 }

  condition:
    any of them
}