rule TTP_XOR_WriteProcessMemory_3273 {
  strings:
    $key_3273 = { 65 01 [2] 57 23 [2] 51 16 [2] 7f 16 [2] 40 0a }

  condition:
    any of them
}