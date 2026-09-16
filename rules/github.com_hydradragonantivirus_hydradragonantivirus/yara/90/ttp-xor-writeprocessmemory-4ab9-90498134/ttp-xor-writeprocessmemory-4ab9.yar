rule TTP_XOR_WriteProcessMemory_4ab9 {
  strings:
    $key_4ab9 = { 1d cb [2] 2f e9 [2] 29 dc [2] 07 dc [2] 38 c0 }

  condition:
    any of them
}