rule TTP_XOR_WriteProcessMemory_a2dc {
  strings:
    $key_a2dc = { f5 ae [2] c7 8c [2] c1 b9 [2] ef b9 [2] d0 a5 }

  condition:
    any of them
}