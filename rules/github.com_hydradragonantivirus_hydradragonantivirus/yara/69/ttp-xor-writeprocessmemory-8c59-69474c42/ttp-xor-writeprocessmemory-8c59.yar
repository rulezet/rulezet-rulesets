rule TTP_XOR_WriteProcessMemory_8c59 {
  strings:
    $key_8c59 = { db 2b [2] e9 09 [2] ef 3c [2] c1 3c [2] fe 20 }

  condition:
    any of them
}