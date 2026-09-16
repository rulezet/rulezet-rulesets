rule TTP_XOR_WriteProcessMemory_63ff {
  strings:
    $key_63ff = { 34 8d [2] 06 af [2] 00 9a [2] 2e 9a [2] 11 86 }

  condition:
    any of them
}