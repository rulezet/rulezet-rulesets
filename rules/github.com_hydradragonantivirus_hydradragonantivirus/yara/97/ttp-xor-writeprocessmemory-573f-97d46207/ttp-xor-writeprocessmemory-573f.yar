rule TTP_XOR_WriteProcessMemory_573f {
  strings:
    $key_573f = { 00 4d [2] 32 6f [2] 34 5a [2] 1a 5a [2] 25 46 }

  condition:
    any of them
}