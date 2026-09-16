rule TTP_XOR_WriteProcessMemory_457a {
  strings:
    $key_457a = { 12 08 [2] 20 2a [2] 26 1f [2] 08 1f [2] 37 03 }

  condition:
    any of them
}