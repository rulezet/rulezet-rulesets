rule TTP_XOR_WriteProcessMemory_2d5a {
  strings:
    $key_2d5a = { 7a 28 [2] 48 0a [2] 4e 3f [2] 60 3f [2] 5f 23 }

  condition:
    any of them
}