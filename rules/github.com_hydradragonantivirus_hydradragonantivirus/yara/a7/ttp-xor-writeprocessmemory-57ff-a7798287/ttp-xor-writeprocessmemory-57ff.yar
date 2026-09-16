rule TTP_XOR_WriteProcessMemory_57ff {
  strings:
    $key_57ff = { 00 8d [2] 32 af [2] 34 9a [2] 1a 9a [2] 25 86 }

  condition:
    any of them
}