rule TTP_XOR_WriteProcessMemory_66c3 {
  strings:
    $key_66c3 = { 31 b1 [2] 03 93 [2] 05 a6 [2] 2b a6 [2] 14 ba }

  condition:
    any of them
}