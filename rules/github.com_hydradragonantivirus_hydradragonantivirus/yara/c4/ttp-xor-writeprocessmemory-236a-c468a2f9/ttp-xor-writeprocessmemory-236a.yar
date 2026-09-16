rule TTP_XOR_WriteProcessMemory_236a {
  strings:
    $key_236a = { 74 18 [2] 46 3a [2] 40 0f [2] 6e 0f [2] 51 13 }

  condition:
    any of them
}