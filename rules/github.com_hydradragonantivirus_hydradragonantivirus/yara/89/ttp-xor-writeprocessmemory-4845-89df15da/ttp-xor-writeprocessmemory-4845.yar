rule TTP_XOR_WriteProcessMemory_4845 {
  strings:
    $key_4845 = { 1f 37 [2] 2d 15 [2] 2b 20 [2] 05 20 [2] 3a 3c }

  condition:
    any of them
}