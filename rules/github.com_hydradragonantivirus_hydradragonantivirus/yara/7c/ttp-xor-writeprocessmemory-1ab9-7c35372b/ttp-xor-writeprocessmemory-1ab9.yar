rule TTP_XOR_WriteProcessMemory_1ab9 {
  strings:
    $key_1ab9 = { 4d cb [2] 7f e9 [2] 79 dc [2] 57 dc [2] 68 c0 }

  condition:
    any of them
}