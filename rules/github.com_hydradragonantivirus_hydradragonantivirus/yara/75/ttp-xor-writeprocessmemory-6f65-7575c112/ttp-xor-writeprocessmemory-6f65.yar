rule TTP_XOR_WriteProcessMemory_6f65 {
  strings:
    $key_6f65 = { 38 17 [2] 0a 35 [2] 0c 00 [2] 22 00 [2] 1d 1c }

  condition:
    any of them
}