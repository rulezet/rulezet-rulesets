rule TTP_XOR_WriteProcessMemory_6149 {
  strings:
    $key_6149 = { 36 3b [2] 04 19 [2] 02 2c [2] 2c 2c [2] 13 30 }

  condition:
    any of them
}