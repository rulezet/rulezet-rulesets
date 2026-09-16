rule TTP_XOR_WriteProcessMemory_394a {
  strings:
    $key_394a = { 6e 38 [2] 5c 1a [2] 5a 2f [2] 74 2f [2] 4b 33 }

  condition:
    any of them
}