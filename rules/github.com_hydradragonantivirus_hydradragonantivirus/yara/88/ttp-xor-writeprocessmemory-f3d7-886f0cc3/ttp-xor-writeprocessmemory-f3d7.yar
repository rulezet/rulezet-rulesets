rule TTP_XOR_WriteProcessMemory_f3d7 {
  strings:
    $key_f3d7 = { a4 a5 [2] 96 87 [2] 90 b2 [2] be b2 [2] 81 ae }

  condition:
    any of them
}