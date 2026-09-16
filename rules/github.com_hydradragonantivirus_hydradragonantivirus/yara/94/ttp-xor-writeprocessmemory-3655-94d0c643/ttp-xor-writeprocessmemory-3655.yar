rule TTP_XOR_WriteProcessMemory_3655 {
  strings:
    $key_3655 = { 61 27 [2] 53 05 [2] 55 30 [2] 7b 30 [2] 44 2c }

  condition:
    any of them
}