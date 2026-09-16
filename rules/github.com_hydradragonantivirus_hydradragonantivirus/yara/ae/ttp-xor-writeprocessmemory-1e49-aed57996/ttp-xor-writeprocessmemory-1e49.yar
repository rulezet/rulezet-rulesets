rule TTP_XOR_WriteProcessMemory_1e49 {
  strings:
    $key_1e49 = { 49 3b [2] 7b 19 [2] 7d 2c [2] 53 2c [2] 6c 30 }

  condition:
    any of them
}