rule TTP_XOR_WriteProcessMemory_117f {
  strings:
    $key_117f = { 46 0d [2] 74 2f [2] 72 1a [2] 5c 1a [2] 63 06 }

  condition:
    any of them
}