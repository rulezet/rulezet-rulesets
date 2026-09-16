rule TTP_XOR_WriteProcessMemory_7310 {
  strings:
    $key_7310 = { 24 62 [2] 16 40 [2] 10 75 [2] 3e 75 [2] 01 69 }

  condition:
    any of them
}