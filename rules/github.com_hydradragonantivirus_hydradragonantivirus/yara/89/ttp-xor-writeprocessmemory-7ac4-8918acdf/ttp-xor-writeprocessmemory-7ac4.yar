rule TTP_XOR_WriteProcessMemory_7ac4 {
  strings:
    $key_7ac4 = { 2d b6 [2] 1f 94 [2] 19 a1 [2] 37 a1 [2] 08 bd }

  condition:
    any of them
}