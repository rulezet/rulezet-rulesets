rule TTP_XOR_WriteProcessMemory_433a {
  strings:
    $key_433a = { 14 48 [2] 26 6a [2] 20 5f [2] 0e 5f [2] 31 43 }

  condition:
    any of them
}