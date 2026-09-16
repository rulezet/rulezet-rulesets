rule TTP_XOR_WriteProcessMemory_6410 {
  strings:
    $key_6410 = { 33 62 [2] 01 40 [2] 07 75 [2] 29 75 [2] 16 69 }

  condition:
    any of them
}