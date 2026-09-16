rule TTP_XOR_WriteProcessMemory_593a {
  strings:
    $key_593a = { 0e 48 [2] 3c 6a [2] 3a 5f [2] 14 5f [2] 2b 43 }

  condition:
    any of them
}