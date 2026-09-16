rule TTP_XOR_WriteProcessMemory_1f41 {
  strings:
    $key_1f41 = { 48 33 [2] 7a 11 [2] 7c 24 [2] 52 24 [2] 6d 38 }

  condition:
    any of them
}