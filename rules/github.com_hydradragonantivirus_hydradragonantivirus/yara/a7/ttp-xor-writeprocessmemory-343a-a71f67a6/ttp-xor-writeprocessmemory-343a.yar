rule TTP_XOR_WriteProcessMemory_343a {
  strings:
    $key_343a = { 63 48 [2] 51 6a [2] 57 5f [2] 79 5f [2] 46 43 }

  condition:
    any of them
}