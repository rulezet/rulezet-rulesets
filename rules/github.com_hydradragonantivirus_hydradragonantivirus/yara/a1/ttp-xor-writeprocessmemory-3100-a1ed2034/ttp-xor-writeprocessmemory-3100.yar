rule TTP_XOR_WriteProcessMemory_3100 {
  strings:
    $key_3100 = { 66 72 [2] 54 50 [2] 52 65 [2] 7c 65 [2] 43 79 }

  condition:
    any of them
}