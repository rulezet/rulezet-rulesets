rule TTP_XOR_WriteProcessMemory_5b4a {
  strings:
    $key_5b4a = { 0c 38 [2] 3e 1a [2] 38 2f [2] 16 2f [2] 29 33 }

  condition:
    any of them
}