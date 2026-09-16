rule TTP_XOR_WriteProcessMemory_5b2a {
  strings:
    $key_5b2a = { 0c 58 [2] 3e 7a [2] 38 4f [2] 16 4f [2] 29 53 }

  condition:
    any of them
}