rule TTP_XOR_WriteProcessMemory_61b9 {
  strings:
    $key_61b9 = { 36 cb [2] 04 e9 [2] 02 dc [2] 2c dc [2] 13 c0 }

  condition:
    any of them
}