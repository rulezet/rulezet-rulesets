rule TTP_XOR_WriteProcessMemory_0ac4 {
  strings:
    $key_0ac4 = { 5d b6 [2] 6f 94 [2] 69 a1 [2] 47 a1 [2] 78 bd }

  condition:
    any of them
}