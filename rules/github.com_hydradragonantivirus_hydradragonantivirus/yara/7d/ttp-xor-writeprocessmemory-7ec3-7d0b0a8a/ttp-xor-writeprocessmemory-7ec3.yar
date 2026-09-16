rule TTP_XOR_WriteProcessMemory_7ec3 {
  strings:
    $key_7ec3 = { 29 b1 [2] 1b 93 [2] 1d a6 [2] 33 a6 [2] 0c ba }

  condition:
    any of them
}