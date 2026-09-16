rule TTP_XOR_WriteProcessMemory_7e3a {
  strings:
    $key_7e3a = { 29 48 [2] 1b 6a [2] 1d 5f [2] 33 5f [2] 0c 43 }

  condition:
    any of them
}