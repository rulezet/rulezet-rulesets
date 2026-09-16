rule TTP_XOR_WriteProcessMemory_783a {
  strings:
    $key_783a = { 2f 48 [2] 1d 6a [2] 1b 5f [2] 35 5f [2] 0a 43 }

  condition:
    any of them
}