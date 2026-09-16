rule TTP_XOR_WriteProcessMemory_4d7f {
  strings:
    $key_4d7f = { 1a 0d [2] 28 2f [2] 2e 1a [2] 00 1a [2] 3f 06 }

  condition:
    any of them
}