rule TTP_XOR_WriteProcessMemory_8ce3 {
  strings:
    $key_8ce3 = { db 91 [2] e9 b3 [2] ef 86 [2] c1 86 [2] fe 9a }

  condition:
    any of them
}