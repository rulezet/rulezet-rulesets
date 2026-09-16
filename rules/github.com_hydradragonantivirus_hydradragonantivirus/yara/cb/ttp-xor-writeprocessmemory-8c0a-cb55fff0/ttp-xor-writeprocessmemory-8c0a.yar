rule TTP_XOR_WriteProcessMemory_8c0a {
  strings:
    $key_8c0a = { db 78 [2] e9 5a [2] ef 6f [2] c1 6f [2] fe 73 }

  condition:
    any of them
}