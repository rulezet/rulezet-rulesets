rule TTP_XOR_WriteProcessMemory_6f41 {
  strings:
    $key_6f41 = { 38 33 [2] 0a 11 [2] 0c 24 [2] 22 24 [2] 1d 38 }

  condition:
    any of them
}