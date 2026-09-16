rule TTP_XOR_WriteProcessMemory_723a {
  strings:
    $key_723a = { 25 48 [2] 17 6a [2] 11 5f [2] 3f 5f [2] 00 43 }

  condition:
    any of them
}