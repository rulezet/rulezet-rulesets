rule TTP_XOR_WriteProcessMemory_6b60 {
  strings:
    $key_6b60 = { 3c 12 [2] 0e 30 [2] 08 05 [2] 26 05 [2] 19 19 }

  condition:
    any of them
}