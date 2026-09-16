rule TTP_XOR_WriteProcessMemory_4825 {
  strings:
    $key_4825 = { 1f 57 [2] 2d 75 [2] 2b 40 [2] 05 40 [2] 3a 5c }

  condition:
    any of them
}