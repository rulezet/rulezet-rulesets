rule TTP_XOR_WriteProcessMemory_6df0 {
  strings:
    $key_6df0 = { 3a 82 [2] 08 a0 [2] 0e 95 [2] 20 95 [2] 1f 89 }

  condition:
    any of them
}