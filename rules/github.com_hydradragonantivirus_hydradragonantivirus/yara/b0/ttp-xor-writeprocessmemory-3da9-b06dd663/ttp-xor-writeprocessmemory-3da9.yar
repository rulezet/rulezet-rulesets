rule TTP_XOR_WriteProcessMemory_3da9 {
  strings:
    $key_3da9 = { 6a db [2] 58 f9 [2] 5e cc [2] 70 cc [2] 4f d0 }

  condition:
    any of them
}