rule TTP_XOR_WriteProcessMemory_453a {
  strings:
    $key_453a = { 12 48 [2] 20 6a [2] 26 5f [2] 08 5f [2] 37 43 }

  condition:
    any of them
}