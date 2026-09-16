rule TTP_XOR_WriteProcessMemory_44c3 {
  strings:
    $key_44c3 = { 13 b1 [2] 21 93 [2] 27 a6 [2] 09 a6 [2] 36 ba }

  condition:
    any of them
}