rule TTP_XOR_WriteProcessMemory_634a {
  strings:
    $key_634a = { 34 38 [2] 06 1a [2] 00 2f [2] 2e 2f [2] 11 33 }

  condition:
    any of them
}