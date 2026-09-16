rule TTP_XOR_WriteProcessMemory_8c6a {
  strings:
    $key_8c6a = { db 18 [2] e9 3a [2] ef 0f [2] c1 0f [2] fe 13 }

  condition:
    any of them
}