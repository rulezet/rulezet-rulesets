rule TTP_XOR_WriteProcessMemory_711a {
  strings:
    $key_711a = { 26 68 [2] 14 4a [2] 12 7f [2] 3c 7f [2] 03 63 }

  condition:
    any of them
}