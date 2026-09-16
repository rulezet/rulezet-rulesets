rule TTP_XOR_WriteProcessMemory_6d7f {
  strings:
    $key_6d7f = { 3a 0d [2] 08 2f [2] 0e 1a [2] 20 1a [2] 1f 06 }

  condition:
    any of them
}