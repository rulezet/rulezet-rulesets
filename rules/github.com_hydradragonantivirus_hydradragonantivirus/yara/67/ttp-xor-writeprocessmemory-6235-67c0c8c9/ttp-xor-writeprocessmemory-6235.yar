rule TTP_XOR_WriteProcessMemory_6235 {
  strings:
    $key_6235 = { 35 47 [2] 07 65 [2] 01 50 [2] 2f 50 [2] 10 4c }

  condition:
    any of them
}