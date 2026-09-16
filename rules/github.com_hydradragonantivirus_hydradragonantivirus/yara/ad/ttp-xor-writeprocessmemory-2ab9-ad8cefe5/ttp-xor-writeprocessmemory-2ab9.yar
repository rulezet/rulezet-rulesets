rule TTP_XOR_WriteProcessMemory_2ab9 {
  strings:
    $key_2ab9 = { 7d cb [2] 4f e9 [2] 49 dc [2] 67 dc [2] 58 c0 }

  condition:
    any of them
}