rule TTP_XOR_WriteProcessMemory_4397 {
  strings:
    $key_4397 = { 14 e5 [2] 26 c7 [2] 20 f2 [2] 0e f2 [2] 31 ee }

  condition:
    any of them
}