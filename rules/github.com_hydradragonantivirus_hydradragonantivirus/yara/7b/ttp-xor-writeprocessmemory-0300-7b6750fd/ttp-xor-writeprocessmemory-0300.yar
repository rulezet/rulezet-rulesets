rule TTP_XOR_WriteProcessMemory_0300 {
  strings:
    $key_0300 = { 54 72 [2] 66 50 [2] 60 65 [2] 4e 65 [2] 71 79 }

  condition:
    any of them
}