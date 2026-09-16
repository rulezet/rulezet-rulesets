rule TTP_XOR_WriteProcessMemory_4a45 {
  strings:
    $key_4a45 = { 1d 37 [2] 2f 15 [2] 29 20 [2] 07 20 [2] 38 3c }

  condition:
    any of them
}