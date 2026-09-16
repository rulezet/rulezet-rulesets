rule TTP_XOR_WriteProcessMemory_6438 {
  strings:
    $key_6438 = { 33 4a [2] 01 68 [2] 07 5d [2] 29 5d [2] 16 41 }

  condition:
    any of them
}