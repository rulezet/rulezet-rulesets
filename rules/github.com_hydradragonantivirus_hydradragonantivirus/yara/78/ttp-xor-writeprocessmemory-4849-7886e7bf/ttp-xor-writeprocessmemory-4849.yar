rule TTP_XOR_WriteProcessMemory_4849 {
  strings:
    $key_4849 = { 1f 3b [2] 2d 19 [2] 2b 2c [2] 05 2c [2] 3a 30 }

  condition:
    any of them
}