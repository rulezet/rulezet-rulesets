rule TTP_XOR_WriteProcessMemory_417f {
  strings:
    $key_417f = { 16 0d [2] 24 2f [2] 22 1a [2] 0c 1a [2] 33 06 }

  condition:
    any of them
}