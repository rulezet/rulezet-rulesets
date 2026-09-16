rule TTP_XOR_WriteProcessMemory_5ab9 {
  strings:
    $key_5ab9 = { 0d cb [2] 3f e9 [2] 39 dc [2] 17 dc [2] 28 c0 }

  condition:
    any of them
}