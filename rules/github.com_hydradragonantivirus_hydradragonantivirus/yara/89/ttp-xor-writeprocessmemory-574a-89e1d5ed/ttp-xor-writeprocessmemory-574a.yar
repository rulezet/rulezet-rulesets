rule TTP_XOR_WriteProcessMemory_574a {
  strings:
    $key_574a = { 00 38 [2] 32 1a [2] 34 2f [2] 1a 2f [2] 25 33 }

  condition:
    any of them
}