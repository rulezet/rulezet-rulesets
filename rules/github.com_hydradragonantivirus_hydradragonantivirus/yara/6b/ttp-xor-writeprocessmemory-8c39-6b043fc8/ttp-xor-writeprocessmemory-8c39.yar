rule TTP_XOR_WriteProcessMemory_8c39 {
  strings:
    $key_8c39 = { db 4b [2] e9 69 [2] ef 5c [2] c1 5c [2] fe 40 }

  condition:
    any of them
}