rule TTP_XOR_WriteProcessMemory_4ec3 {
  strings:
    $key_4ec3 = { 19 b1 [2] 2b 93 [2] 2d a6 [2] 03 a6 [2] 3c ba }

  condition:
    any of them
}