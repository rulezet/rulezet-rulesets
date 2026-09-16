rule TTP_XOR_WriteProcessMemory_e2d7 {
  strings:
    $key_e2d7 = { b5 a5 [2] 87 87 [2] 81 b2 [2] af b2 [2] 90 ae }

  condition:
    any of them
}