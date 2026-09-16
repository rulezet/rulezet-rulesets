rule TTP_XOR_WriteProcessMemory_7177 {
  strings:
    $key_7177 = { 26 05 [2] 14 27 [2] 12 12 [2] 3c 12 [2] 03 0e }

  condition:
    any of them
}