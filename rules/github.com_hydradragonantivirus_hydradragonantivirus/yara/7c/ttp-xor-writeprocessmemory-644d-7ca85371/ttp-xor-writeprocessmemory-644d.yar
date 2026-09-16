rule TTP_XOR_WriteProcessMemory_644d {
  strings:
    $key_644d = { 33 3f [2] 01 1d [2] 07 28 [2] 29 28 [2] 16 34 }

  condition:
    any of them
}