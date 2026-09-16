rule TTP_XOR_WriteProcessMemory_0700 {
  strings:
    $key_0700 = { 50 72 [2] 62 50 [2] 64 65 [2] 4a 65 [2] 75 79 }

  condition:
    any of them
}