rule TTP_XOR_WriteProcessMemory_4a49 {
  strings:
    $key_4a49 = { 1d 3b [2] 2f 19 [2] 29 2c [2] 07 2c [2] 38 30 }

  condition:
    any of them
}