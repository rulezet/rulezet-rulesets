rule TTP_XOR_WriteProcessMemory_2df0 {
  strings:
    $key_2df0 = { 7a 82 [2] 48 a0 [2] 4e 95 [2] 60 95 [2] 5f 89 }

  condition:
    any of them
}