rule TTP_XOR_WriteProcessMemory_1ec3 {
  strings:
    $key_1ec3 = { 49 b1 [2] 7b 93 [2] 7d a6 [2] 53 a6 [2] 6c ba }

  condition:
    any of them
}