rule TTP_XOR_WriteProcessMemory_3626 {
  strings:
    $key_3626 = { 61 54 [2] 53 76 [2] 55 43 [2] 7b 43 [2] 44 5f }

  condition:
    any of them
}