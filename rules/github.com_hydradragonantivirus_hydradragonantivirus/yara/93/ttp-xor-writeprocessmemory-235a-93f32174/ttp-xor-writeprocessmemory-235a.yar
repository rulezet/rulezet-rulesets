rule TTP_XOR_WriteProcessMemory_235a {
  strings:
    $key_235a = { 74 28 [2] 46 0a [2] 40 3f [2] 6e 3f [2] 51 23 }

  condition:
    any of them
}