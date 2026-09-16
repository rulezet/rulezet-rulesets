rule TTP_XOR_WriteProcessMemory_1255 {
  strings:
    $key_1255 = { 45 27 [2] 77 05 [2] 71 30 [2] 5f 30 [2] 60 2c }

  condition:
    any of them
}