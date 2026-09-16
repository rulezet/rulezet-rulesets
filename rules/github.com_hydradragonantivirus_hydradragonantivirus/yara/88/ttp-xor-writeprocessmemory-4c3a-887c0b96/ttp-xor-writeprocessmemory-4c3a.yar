rule TTP_XOR_WriteProcessMemory_4c3a {
  strings:
    $key_4c3a = { 1b 48 [2] 29 6a [2] 2f 5f [2] 01 5f [2] 3e 43 }

  condition:
    any of them
}