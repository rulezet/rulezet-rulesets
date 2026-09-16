rule TTP_XOR_WriteProcessMemory_0ab9 {
  strings:
    $key_0ab9 = { 5d cb [2] 6f e9 [2] 69 dc [2] 47 dc [2] 78 c0 }

  condition:
    any of them
}