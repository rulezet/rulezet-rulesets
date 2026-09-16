rule TTP_XOR_WriteProcessMemory_7c4a {
  strings:
    $key_7c4a = { 2b 38 [2] 19 1a [2] 1f 2f [2] 31 2f [2] 0e 33 }

  condition:
    any of them
}