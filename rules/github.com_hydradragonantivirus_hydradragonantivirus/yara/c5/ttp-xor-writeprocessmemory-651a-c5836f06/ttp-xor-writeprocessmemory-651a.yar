rule TTP_XOR_WriteProcessMemory_651a {
  strings:
    $key_651a = { 32 68 [2] 00 4a [2] 06 7f [2] 28 7f [2] 17 63 }

  condition:
    any of them
}