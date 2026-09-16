rule TTP_XOR_WriteProcessMemory_6085 {
  strings:
    $key_6085 = { 37 f7 [2] 05 d5 [2] 03 e0 [2] 2d e0 [2] 12 fc }

  condition:
    any of them
}