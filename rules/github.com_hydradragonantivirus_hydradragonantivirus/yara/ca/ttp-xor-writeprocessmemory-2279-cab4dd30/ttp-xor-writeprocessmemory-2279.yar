rule TTP_XOR_WriteProcessMemory_2279 {
  strings:
    $key_2279 = { 75 0b [2] 47 29 [2] 41 1c [2] 6f 1c [2] 50 00 }

  condition:
    any of them
}