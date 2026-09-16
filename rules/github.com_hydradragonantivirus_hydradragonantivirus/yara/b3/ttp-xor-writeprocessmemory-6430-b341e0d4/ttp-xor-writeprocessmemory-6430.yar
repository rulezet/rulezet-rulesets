rule TTP_XOR_WriteProcessMemory_6430 {
  strings:
    $key_6430 = { 33 42 [2] 01 60 [2] 07 55 [2] 29 55 [2] 16 49 }

  condition:
    any of them
}