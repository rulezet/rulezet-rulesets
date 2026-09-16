rule TTP_XOR_WriteProcessMemory_3966 {
  strings:
    $key_3966 = { 6e 14 [2] 5c 36 [2] 5a 03 [2] 74 03 [2] 4b 1f }

  condition:
    any of them
}