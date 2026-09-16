rule TTP_XOR_WriteProcessMemory_3256 {
  strings:
    $key_3256 = { 65 24 [2] 57 06 [2] 51 33 [2] 7f 33 [2] 40 2f }

  condition:
    any of them
}