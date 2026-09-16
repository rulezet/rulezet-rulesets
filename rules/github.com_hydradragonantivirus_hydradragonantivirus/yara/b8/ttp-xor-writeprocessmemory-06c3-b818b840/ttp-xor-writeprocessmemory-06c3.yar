rule TTP_XOR_WriteProcessMemory_06c3 {
  strings:
    $key_06c3 = { 51 b1 [2] 63 93 [2] 65 a6 [2] 4b a6 [2] 74 ba }

  condition:
    any of them
}