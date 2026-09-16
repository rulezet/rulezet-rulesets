rule TTP_XOR_WriteProcessMemory_8cb5 {
  strings:
    $key_8cb5 = { db c7 [2] e9 e5 [2] ef d0 [2] c1 d0 [2] fe cc }

  condition:
    any of them
}