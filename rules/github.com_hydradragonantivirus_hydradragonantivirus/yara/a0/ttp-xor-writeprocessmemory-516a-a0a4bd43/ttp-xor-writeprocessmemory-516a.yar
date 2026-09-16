rule TTP_XOR_WriteProcessMemory_516a {
  strings:
    $key_516a = { 06 18 [2] 34 3a [2] 32 0f [2] 1c 0f [2] 23 13 }

  condition:
    any of them
}