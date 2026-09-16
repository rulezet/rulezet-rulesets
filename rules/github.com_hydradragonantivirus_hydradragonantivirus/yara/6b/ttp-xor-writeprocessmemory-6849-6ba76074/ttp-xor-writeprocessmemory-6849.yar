rule TTP_XOR_WriteProcessMemory_6849 {
  strings:
    $key_6849 = { 3f 3b [2] 0d 19 [2] 0b 2c [2] 25 2c [2] 1a 30 }

  condition:
    any of them
}