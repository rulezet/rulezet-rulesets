rule TTP_XOR_WriteProcessMemory_163a {
  strings:
    $key_163a = { 41 48 [2] 73 6a [2] 75 5f [2] 5b 5f [2] 64 43 }

  condition:
    any of them
}