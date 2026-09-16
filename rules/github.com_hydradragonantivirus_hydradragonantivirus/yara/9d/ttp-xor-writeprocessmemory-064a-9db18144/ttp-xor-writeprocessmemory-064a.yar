rule TTP_XOR_WriteProcessMemory_064a {
  strings:
    $key_064a = { 51 38 [2] 63 1a [2] 65 2f [2] 4b 2f [2] 74 33 }

  condition:
    any of them
}