rule TTP_XOR_WriteProcessMemory_1c06 {
  strings:
    $key_1c06 = { 4b 74 [2] 79 56 [2] 7f 63 [2] 51 63 [2] 6e 7f }

  condition:
    any of them
}