rule TTP_XOR_WriteProcessMemory_0768 {
  strings:
    $key_0768 = { 50 1a [2] 62 38 [2] 64 0d [2] 4a 0d [2] 75 11 }

  condition:
    any of them
}