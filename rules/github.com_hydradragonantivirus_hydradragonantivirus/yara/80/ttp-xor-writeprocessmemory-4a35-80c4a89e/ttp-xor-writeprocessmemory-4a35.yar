rule TTP_XOR_WriteProcessMemory_4a35 {
  strings:
    $key_4a35 = { 1d 47 [2] 2f 65 [2] 29 50 [2] 07 50 [2] 38 4c }

  condition:
    any of them
}