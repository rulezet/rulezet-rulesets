rule TTP_XOR_WriteProcessMemory_5d2a {
  strings:
    $key_5d2a = { 0a 58 [2] 38 7a [2] 3e 4f [2] 10 4f [2] 2f 53 }

  condition:
    any of them
}