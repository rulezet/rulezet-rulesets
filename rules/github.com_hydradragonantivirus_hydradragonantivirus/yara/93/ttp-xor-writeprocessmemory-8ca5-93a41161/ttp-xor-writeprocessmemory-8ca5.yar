rule TTP_XOR_WriteProcessMemory_8ca5 {
  strings:
    $key_8ca5 = { db d7 [2] e9 f5 [2] ef c0 [2] c1 c0 [2] fe dc }

  condition:
    any of them
}