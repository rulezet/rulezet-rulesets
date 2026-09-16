rule TTP_XOR_WriteProcessMemory_6d5a {
  strings:
    $key_6d5a = { 3a 28 [2] 08 0a [2] 0e 3f [2] 20 3f [2] 1f 23 }

  condition:
    any of them
}