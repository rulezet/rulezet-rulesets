rule TTP_XOR_WriteProcessMemory_3f91 {
  strings:
    $key_3f91 = { 68 e3 [2] 5a c1 [2] 5c f4 [2] 72 f4 [2] 4d e8 }

  condition:
    any of them
}