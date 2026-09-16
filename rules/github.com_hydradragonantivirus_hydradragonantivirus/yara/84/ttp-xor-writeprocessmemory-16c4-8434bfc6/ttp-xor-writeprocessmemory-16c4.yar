rule TTP_XOR_WriteProcessMemory_16c4 {
  strings:
    $key_16c4 = { 41 b6 [2] 73 94 [2] 75 a1 [2] 5b a1 [2] 64 bd }

  condition:
    any of them
}