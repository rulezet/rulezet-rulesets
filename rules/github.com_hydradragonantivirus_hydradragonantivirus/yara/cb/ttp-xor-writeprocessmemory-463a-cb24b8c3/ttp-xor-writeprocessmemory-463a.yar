rule TTP_XOR_WriteProcessMemory_463a {
  strings:
    $key_463a = { 11 48 [2] 23 6a [2] 25 5f [2] 0b 5f [2] 34 43 }

  condition:
    any of them
}