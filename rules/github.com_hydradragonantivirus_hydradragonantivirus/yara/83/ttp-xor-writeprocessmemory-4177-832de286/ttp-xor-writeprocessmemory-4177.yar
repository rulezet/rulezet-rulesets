rule TTP_XOR_WriteProcessMemory_4177 {
  strings:
    $key_4177 = { 16 05 [2] 24 27 [2] 22 12 [2] 0c 12 [2] 33 0e }

  condition:
    any of them
}