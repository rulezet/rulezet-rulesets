rule TTP_XOR_WriteProcessMemory_6b3a {
  strings:
    $key_6b3a = { 3c 48 [2] 0e 6a [2] 08 5f [2] 26 5f [2] 19 43 }

  condition:
    any of them
}