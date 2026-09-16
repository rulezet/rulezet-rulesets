rule TTP_XOR_WriteProcessMemory_4c06 {
  strings:
    $key_4c06 = { 1b 74 [2] 29 56 [2] 2f 63 [2] 01 63 [2] 3e 7f }

  condition:
    any of them
}