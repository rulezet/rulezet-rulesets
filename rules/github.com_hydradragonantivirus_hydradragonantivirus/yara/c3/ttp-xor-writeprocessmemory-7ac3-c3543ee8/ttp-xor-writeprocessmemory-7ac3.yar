rule TTP_XOR_WriteProcessMemory_7ac3 {
  strings:
    $key_7ac3 = { 2d b1 [2] 1f 93 [2] 19 a6 [2] 37 a6 [2] 08 ba }

  condition:
    any of them
}