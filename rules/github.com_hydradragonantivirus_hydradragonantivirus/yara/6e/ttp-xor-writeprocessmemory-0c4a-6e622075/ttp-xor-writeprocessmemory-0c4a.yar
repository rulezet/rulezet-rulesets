rule TTP_XOR_WriteProcessMemory_0c4a {
  strings:
    $key_0c4a = { 5b 38 [2] 69 1a [2] 6f 2f [2] 41 2f [2] 7e 33 }

  condition:
    any of them
}