rule TTP_XOR_WriteProcessMemory_6406 {
  strings:
    $key_6406 = { 33 74 [2] 01 56 [2] 07 63 [2] 29 63 [2] 16 7f }

  condition:
    any of them
}