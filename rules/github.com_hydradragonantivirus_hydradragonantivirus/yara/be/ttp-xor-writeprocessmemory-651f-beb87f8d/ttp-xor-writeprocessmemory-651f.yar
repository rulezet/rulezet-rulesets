rule TTP_XOR_WriteProcessMemory_651f {
  strings:
    $key_651f = { 32 6d [2] 00 4f [2] 06 7a [2] 28 7a [2] 17 66 }

  condition:
    any of them
}