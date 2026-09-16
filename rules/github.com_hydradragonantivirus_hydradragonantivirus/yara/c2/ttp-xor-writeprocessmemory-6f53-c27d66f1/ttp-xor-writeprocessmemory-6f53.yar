rule TTP_XOR_WriteProcessMemory_6f53 {
  strings:
    $key_6f53 = { 38 21 [2] 0a 03 [2] 0c 36 [2] 22 36 [2] 1d 2a }

  condition:
    any of them
}