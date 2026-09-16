rule TTP_XOR_WriteProcessMemory_1c76 {
  strings:
    $key_1c76 = { 4b 04 [2] 79 26 [2] 7f 13 [2] 51 13 [2] 6e 0f }

  condition:
    any of them
}