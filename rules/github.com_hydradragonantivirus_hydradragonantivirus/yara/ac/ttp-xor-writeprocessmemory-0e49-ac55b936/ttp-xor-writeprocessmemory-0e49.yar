rule TTP_XOR_WriteProcessMemory_0e49 {
  strings:
    $key_0e49 = { 59 3b [2] 6b 19 [2] 6d 2c [2] 43 2c [2] 7c 30 }

  condition:
    any of them
}