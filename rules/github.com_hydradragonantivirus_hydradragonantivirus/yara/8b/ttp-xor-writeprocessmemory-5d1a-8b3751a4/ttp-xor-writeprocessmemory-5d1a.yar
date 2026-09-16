rule TTP_XOR_WriteProcessMemory_5d1a {
  strings:
    $key_5d1a = { 0a 68 [2] 38 4a [2] 3e 7f [2] 10 7f [2] 2f 63 }

  condition:
    any of them
}