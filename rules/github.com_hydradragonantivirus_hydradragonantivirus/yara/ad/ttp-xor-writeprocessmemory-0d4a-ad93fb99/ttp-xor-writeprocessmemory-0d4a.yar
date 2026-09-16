rule TTP_XOR_WriteProcessMemory_0d4a {
  strings:
    $key_0d4a = { 5a 38 [2] 68 1a [2] 6e 2f [2] 40 2f [2] 7f 33 }

  condition:
    any of them
}