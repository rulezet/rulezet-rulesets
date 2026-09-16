rule TTP_XOR_WriteProcessMemory_717f {
  strings:
    $key_717f = { 26 0d [2] 14 2f [2] 12 1a [2] 3c 1a [2] 03 06 }

  condition:
    any of them
}