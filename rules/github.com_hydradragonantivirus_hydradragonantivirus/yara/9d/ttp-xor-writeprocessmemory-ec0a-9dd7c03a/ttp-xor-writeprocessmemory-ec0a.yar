rule TTP_XOR_WriteProcessMemory_ec0a {
  strings:
    $key_ec0a = { bb 78 [2] 89 5a [2] 8f 6f [2] a1 6f [2] 9e 73 }

  condition:
    any of them
}