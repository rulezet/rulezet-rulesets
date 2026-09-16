rule TTP_XOR_WriteProcessMemory_0ac3 {
  strings:
    $key_0ac3 = { 5d b1 [2] 6f 93 [2] 69 a6 [2] 47 a6 [2] 78 ba }

  condition:
    any of them
}