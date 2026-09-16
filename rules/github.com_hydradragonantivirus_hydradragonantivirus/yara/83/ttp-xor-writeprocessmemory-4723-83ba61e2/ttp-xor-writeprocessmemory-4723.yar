rule TTP_XOR_WriteProcessMemory_4723 {
  strings:
    $key_4723 = { 10 51 [2] 22 73 [2] 24 46 [2] 0a 46 [2] 35 5a }

  condition:
    any of them
}