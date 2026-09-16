rule TTP_XOR_WriteProcessMemory_8cec {
  strings:
    $key_8cec = { db 9e [2] e9 bc [2] ef 89 [2] c1 89 [2] fe 95 }

  condition:
    any of them
}