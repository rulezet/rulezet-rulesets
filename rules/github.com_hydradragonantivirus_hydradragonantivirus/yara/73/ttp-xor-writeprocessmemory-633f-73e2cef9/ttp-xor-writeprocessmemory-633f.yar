rule TTP_XOR_WriteProcessMemory_633f {
  strings:
    $key_633f = { 34 4d [2] 06 6f [2] 00 5a [2] 2e 5a [2] 11 46 }

  condition:
    any of them
}