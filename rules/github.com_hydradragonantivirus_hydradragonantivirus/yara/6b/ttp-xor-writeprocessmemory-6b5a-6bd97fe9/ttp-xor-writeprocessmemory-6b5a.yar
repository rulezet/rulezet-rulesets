rule TTP_XOR_WriteProcessMemory_6b5a {
  strings:
    $key_6b5a = { 3c 28 [2] 0e 0a [2] 08 3f [2] 26 3f [2] 19 23 }

  condition:
    any of them
}