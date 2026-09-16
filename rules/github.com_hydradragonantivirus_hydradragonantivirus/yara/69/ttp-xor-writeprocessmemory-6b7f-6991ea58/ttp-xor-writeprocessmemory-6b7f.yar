rule TTP_XOR_WriteProcessMemory_6b7f {
  strings:
    $key_6b7f = { 3c 0d [2] 0e 2f [2] 08 1a [2] 26 1a [2] 19 06 }

  condition:
    any of them
}