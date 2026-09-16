rule TTP_XOR_WriteProcessMemory_6486 {
  strings:
    $key_6486 = { 33 f4 [2] 01 d6 [2] 07 e3 [2] 29 e3 [2] 16 ff }

  condition:
    any of them
}